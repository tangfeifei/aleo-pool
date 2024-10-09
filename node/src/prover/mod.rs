// Copyright (C) 2019-2023 Aleo Systems Inc.
// This file is part of the snarkOS library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod poolmessage;
mod router;

use crate::traits::NodeInterface;
use snarkos_account::Account;
use snarkos_node_bft::ledger_service::ProverLedgerService;
use snarkos_node_router::{
    messages::{Message, NodeType, UnconfirmedSolution},
    Heartbeat, Inbound, Outbound, Router, Routing,
};
use snarkos_node_sync::{BlockSync, BlockSyncMode};
use snarkos_node_tcp::{
    protocols::{Disconnect, Handshake, OnConnect, Reading, Writing},
    P2P,
};
use snarkvm::console::account::Address;
use snarkvm::{
    ledger::narwhal::Data,
    prelude::{
        block::{Block, Header},
        puzzle::{Puzzle, Solution},
        store::ConsensusStorage,
        Network,
    },
    synthesizer::VM,
};

use aleo_std::StorageMode;
use anyhow::Result;
use colored::Colorize;
use core::{marker::PhantomData, time::Duration};
use parking_lot::{Mutex, RwLock};
use rand::{rngs::OsRng, CryptoRng, Rng, thread_rng, RngCore};
use snarkos_node_bft::helpers::{assign_to_worker, fmt_id};
use std::{net::SocketAddr, sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    Arc,
}};
use tokio::task::JoinHandle;

use futures::SinkExt;
use futures::StreamExt;
use native_tls::{Identity, TlsAcceptor as NativeTlsAcceptor};
use snarkvm::prelude::Ledger;
use poolmessage::{PoolData, PoolMessageCS, PoolMessageSC};
use tokio::{
    io::{split, AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::{broadcast, mpsc, oneshot},
    task,
};
use tokio_native_tls::{TlsAcceptor, TlsStream};
use tokio_util::codec::{FramedRead, FramedWrite};
use std::collections::HashMap;
use chrono::prelude::*;
extern crate chrono;
use snarkos_node_consensus::Consensus;
use snarkos_node_rest::Rest;
use serde::{Deserialize, Serialize};

type ServerRouter<N> = broadcast::Sender<ServerRequest<N>>;
type ServerHandler<N> = broadcast::Receiver<ServerRequest<N>>;
type ClientRouter<N> = mpsc::Sender<ClientRequest<N>>;
type ClientHandler<N> = mpsc::Receiver<ClientRequest<N>>;

#[derive(Debug, Clone)]
pub enum ServerRequest<N: Network> {
    Notify(u64, u64, N::BlockHash),
    Exit,
}

pub enum ClientRequest<N: Network> {
    /// submit := (work_id, reserve, prover_solution)
    Submit(u32, u64, PoolData<Solution<N>>),
    Exit,
}

/// A prover is a light node, capable of producing proofs for consensus.
#[derive(Clone)]
pub struct Prover<N: Network, C: ConsensusStorage<N>> {
    /// The router of the node.
    router: Router<N>,
    /// The REST server of the node.
    rest: Option<Rest<N, C, Self>>,
    /// The sync module.
    sync: Arc<BlockSync<N>>,
    /// The genesis block.
    genesis: Block<N>,
    /// The puzzle.
    puzzle: Puzzle<N>,
    /// The latest epoch hash.
    latest_epoch_hash: Arc<RwLock<Option<N::BlockHash>>>,
    /// The latest block header.
    latest_block_header: Arc<RwLock<Option<Header<N>>>>,
    /// The number of puzzle instances.
    puzzle_instances: Arc<AtomicU8>,
    /// The maximum number of puzzle instances.
    max_puzzle_instances: u8,
    /// The spawned handles.
    handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    /// The shutdown signal.
    shutdown: Arc<AtomicBool>,

    server_router: ServerRouter<N>,
    // provers 活跃连接存储
    peers: Arc<Mutex<HashMap<SocketAddr, i64>>>,
    /// PhantomData.
    _phantom: PhantomData<C>,
}

impl<N: Network, C: ConsensusStorage<N>> Prover<N, C> {
    /// Initializes a new prover node.
    pub async fn new(
        pool_ip: SocketAddr,
        c_address: Address<N>,
        c_rate: u32,
        node_ip: SocketAddr,
        account: Account<N>,
        trusted_peers: &[SocketAddr],
        genesis: Block<N>,
        storage_mode: StorageMode,
        shutdown: Arc<AtomicBool>,
        rest_ip: Option<SocketAddr>,
    ) -> Result<Self> {
        // Initialize the signal handler.
        let signal_node = Self::handle_signals(shutdown.clone());

        // Initialize the ledger.
        let ledger = Ledger::<N, C>::load(genesis.clone(), storage_mode.clone())?;
        // Initialize the ledger service.
        let ledger_service = Arc::new(ProverLedgerService::new());
        // Initialize the sync module.
        let sync = BlockSync::new(BlockSyncMode::Router, ledger_service.clone());
        // Determine if the prover should allow external peers.
        let allow_external_peers = true;
        // Initialize the node router.
        let router = Router::new(
            node_ip,
            NodeType::Prover,
            account,
            trusted_peers,
            Self::MAXIMUM_NUMBER_OF_PEERS as u16,
            allow_external_peers,
            matches!(storage_mode, StorageMode::Development(_)),
        )
        .await?;

        // Compute the maximum number of puzzle instances.
        let max_puzzle_instances = num_cpus::get().saturating_sub(2).clamp(1, 6);

        let (server_router, _) = broadcast::channel(1024);
        let (client_router, client_handler) = mpsc::channel(1024);

        // Initialize the node.
        let mut node = Self {
            router,
            sync: Arc::new(sync),
            genesis,
            puzzle: VM::<N, C>::new_puzzle()?,
            latest_epoch_hash: Default::default(),
            latest_block_header: Default::default(),
            puzzle_instances: Default::default(),
            max_puzzle_instances: u8::try_from(max_puzzle_instances)?,
            handles: Default::default(),
            shutdown,
            rest: None,
            server_router: server_router.clone(),
            peers: Arc::new(Mutex::new(HashMap::new())),
            _phantom: Default::default(),
        };

        // Initialize the REST server.
        if let Some(rest_ip) = rest_ip {
            node.rest = Some(Rest::start(rest_ip, 20, None, ledger, Arc::new(node.clone())).await?);
        }

        node.start_pool_server(pool_ip, c_address, c_rate, client_router.clone(), server_router).await?;

        node.dispatch_jobs().await?;

        node.handle_clients_commit(client_handler).await?;
        // Initialize the routing.
        node.initialize_routing().await;
        // Initialize the puzzle.
        // node.initialize_puzzle().await;
        // Initialize the notification message loop.
        node.handles.lock().push(crate::start_notification_message_loop());
        // Pass the node to the signal handler.
        let _ = signal_node.set(node.clone());
        // Return the node.
        Ok(node)
    }
}

#[async_trait]
impl<N: Network, C: ConsensusStorage<N>> NodeInterface<N> for Prover<N, C> {
    /// Shuts down the node.
    async fn shut_down(&self) {
        info!("Shutting down...");

        let _ = self.server_router.send(ServerRequest::Exit);

        // Shut down the puzzle.
        debug!("Shutting down the puzzle...");
        self.shutdown.store(true, Ordering::Relaxed);

        // Abort the tasks.
        debug!("Shutting down the prover...");
        self.handles.lock().iter().for_each(|handle| handle.abort());

        // Shut down the router.
        self.router.shut_down().await;

        info!("Node has shut down.");
    }
}

impl<N: Network, C: ConsensusStorage<N>> Prover<N, C> {
    /// Initialize a new instance of the puzzle.
    async fn initialize_puzzle(&self) {
        for _ in 0..self.max_puzzle_instances {
            let prover = self.clone();
            self.handles.lock().push(tokio::spawn(async move {
                prover.puzzle_loop().await;
            }));
        }
    }

    /// Executes an instance of the puzzle.
    async fn puzzle_loop(&self) {
        loop {
            // If the node is not connected to any peers, then skip this iteration.
            if self.router.number_of_connected_peers() == 0 {
                debug!("Skipping an iteration of the puzzle (no connected peers)");
                tokio::time::sleep(Duration::from_secs(N::ANCHOR_TIME as u64)).await;
                continue;
            }

            // If the number of instances of the puzzle exceeds the maximum, then skip this iteration.
            if self.num_puzzle_instances() > self.max_puzzle_instances {
                // Sleep for a brief period of time.
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }

            // Read the latest epoch hash.
            let latest_epoch_hash = *self.latest_epoch_hash.read();
            // Read the latest state.
            let latest_state = self
                .latest_block_header
                .read()
                .as_ref()
                .map(|header| (header.coinbase_target(), header.proof_target()));

            // If the latest epoch hash and latest state exists, then proceed to generate a solution.
            if let (Some(epoch_hash), Some((coinbase_target, proof_target))) = (latest_epoch_hash, latest_state) {
                // Execute the puzzle.
                let prover = self.clone();
                let result = tokio::task::spawn_blocking(move || {
                    prover.puzzle_iteration(epoch_hash, coinbase_target, proof_target, &mut OsRng)
                })
                .await;

                // If the prover found a solution, then broadcast it.
                if let Ok(Some((solution_target, solution))) = result {
                    info!("Found a Solution '{}' (Proof Target {solution_target})", solution.id());
                    // Broadcast the solution.
                    self.broadcast_solution(solution);
                }
            } else {
                // Otherwise, sleep for a brief period of time, to await for puzzle state.
                tokio::time::sleep(Duration::from_secs(1)).await;
            }

            // If the Ctrl-C handler registered the signal, stop the prover.
            if self.shutdown.load(Ordering::Relaxed) {
                debug!("Shutting down the puzzle...");
                break;
            }
        }
    }

    /// Performs one iteration of the puzzle.
    fn puzzle_iteration<R: Rng + CryptoRng>(
        &self,
        epoch_hash: N::BlockHash,
        coinbase_target: u64,
        proof_target: u64,
        rng: &mut R,
    ) -> Option<(u64, Solution<N>)> {
        // Increment the puzzle instances.
        self.increment_puzzle_instances();

        debug!(
            "Proving 'Puzzle' for Epoch '{}' {}",
            fmt_id(epoch_hash),
            format!("(Coinbase Target {coinbase_target}, Proof Target {proof_target})").dimmed()
        );

        // Compute the solution.
        let result =
            self.puzzle.prove(epoch_hash, self.address(), rng.gen(), Some(proof_target)).ok().and_then(|solution| {
                self.puzzle.get_proof_target(&solution).ok().map(|solution_target| (solution_target, solution))
            });

        // Decrement the puzzle instances.
        self.decrement_puzzle_instances();
        // Return the result.
        result
    }

    /// Broadcasts the solution to the network.
    fn broadcast_solution(&self, solution: Solution<N>) {
        // Prepare the unconfirmed solution message.
        let message = Message::UnconfirmedSolution(UnconfirmedSolution {
            solution_id: solution.id(),
            solution: Data::Object(solution),
        });
        // Propagate the "UnconfirmedSolution".
        self.propagate(message, &[]);
    }

    /// Returns the current number of puzzle instances.
    fn num_puzzle_instances(&self) -> u8 {
        self.puzzle_instances.load(Ordering::Relaxed)
    }

    /// Increments the number of puzzle instances.
    fn increment_puzzle_instances(&self) {
        self.puzzle_instances.fetch_add(1, Ordering::Relaxed);
        #[cfg(debug_assertions)]
        trace!("Number of Instances - {}", self.num_puzzle_instances());
    }

    /// Decrements the number of puzzle instances.
    fn decrement_puzzle_instances(&self) {
        self.puzzle_instances.fetch_sub(1, Ordering::Relaxed);
        #[cfg(debug_assertions)]
        trace!("Number of Instances - {}", self.num_puzzle_instances());
    }
}

impl<N: Network, C: ConsensusStorage<N>> Prover<N, C> {
    async fn start_pool_server(
        &self,
        pool_ip: SocketAddr,
        c_address: Address<N>,
        c_rate: u32,
        client_router: ClientRouter<N>,
        server_router: broadcast::Sender<ServerRequest<N>>,
    ) -> Result<()> {
        let (router, handler) = oneshot::channel();

        let prover = self.clone();
        let prover2 = prover.clone();

        let handle = task::spawn(async move {
            let _ = router.send(());
            let identity = Identity::from_pkcs12(include_bytes!("identity.pfx"), "aleo.9.4").unwrap();
            let native_tls_acceptor = NativeTlsAcceptor::builder(identity).build().unwrap();
            let tls_acceptor = TlsAcceptor::from(native_tls_acceptor);

            let listener = TcpListener::bind(pool_ip).await.unwrap();
            info!("ssl pool server is listening on {}", pool_ip);

            let prover = prover.clone();

            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        info!("new worker connected: {}", addr);
                        let tls_acceptor = tls_acceptor.clone();
                        let client_router = client_router.clone();

                        let mut server_handler = server_router.subscribe();
                        let prover = prover.clone();

                        task::spawn(async move {
                            let ip_addr = socket.peer_addr().unwrap();
                            let tls_stream = tls_acceptor.accept(socket).await;
                            if let Ok(tls_stream) = tls_stream {
                                if let Err(e) = prover
                                    .handle_client::<TlsStream<TcpStream>>(
                                        c_address,
                                        c_rate,
                                        ip_addr,
                                        tls_stream,
                                        client_router.clone(),
                                        &mut server_handler,
                                    )
                                    .await
                                {
                                    error!("error handling worker {}: {:?}", addr, e);
                                }
                            }
                            info!("worker {} disconnected", addr);
                        });
                    }

                    Err(error) => error!("accept error: {}", error),
                }
            }
        });

        self.handles.lock().push(handle);
        let _ = handler.await;
        Ok(())
    }

    async fn handle_client<T: AsyncRead + AsyncWrite>(
        &self,
        c_address: Address<N>,
        c_rate: u32,
        ip_addr: SocketAddr,
        stream: T,
        client_router: ClientRouter<N>,
        server_handler: &mut broadcast::Receiver<ServerRequest<N>>,
    ) -> Result<()> {
        let (reader, writer) = split(stream);
        let mut framed_read = FramedRead::new(reader, PoolMessageCS::Unused::<N>);
        let mut framed_write = FramedWrite::new(writer, PoolMessageSC::Unused::<N>);

        let worker_ip = ip_addr.ip().to_string();
        let mut worker_name = "".to_string();
        let mut worker_address = "".to_string();
        let mut worker_version = "".to_string();
        let mut worker_solutions:Arc<Mutex<HashMap<String, PoolSolution>>> = Arc::new(Mutex::new(HashMap::new()));
        let mut report_solution_ticker = tokio::time::interval(Duration::from_secs(60));
        // 环境变量 是否开启api提交机器信息 (hashRate, machine info)
        let enable_report_worker_log = std::env::var("ENABLE_REPORT_WORKER_LOG").unwrap_or("false".to_string()).to_lowercase() == "true".to_string();
        // 环境变量 是否开启api提交用户solution
        let enable_report_solution = std::env::var("ENABLE_REPORT_SOLUTION").unwrap_or("false".to_string()).to_lowercase() == "true".to_string();

        if let Some(Ok(msg)) = framed_read.next().await {
            match msg {
                PoolMessageCS::Connect(worker_type, address_type, v_major, v_minor, v_path, w_name, w_address) => {
                   // info!("worker accepted: {:?}", ip_addr);
                    info!("received Connect. param: [{}, {}, {}, {}, {}, {}, {}] client: {}", worker_type, address_type, v_major, v_minor, v_path, w_name, w_address, ip_addr.clone().to_string());
                    worker_name = w_name;
                    worker_address = w_address;
                    worker_version = format!("v{}.{}.{}", v_major, v_minor, v_path);
                    // 新peer 加入
                    self.set_peer(ip_addr.clone());

                    let worker_id = rand::random::<u32>();

                    let message = PoolMessageSC::ConnectAck(true, c_address, c_rate, worker_id);
                    if let Err(error) = framed_write.send(message).await {
                        error!("[send connectack to worker] {}", error);
                    } else {
                        let latest_state = self.latest_block_header.read().as_ref().and_then(|header| {
                            self.latest_epoch_hash.read().as_ref().map(|epoch_hash| {
                                info!("Found latest block header and epoch hash");
                                (header.height(), header.coinbase_target(), header.proof_target(), *epoch_hash)
                            })
                        });
                        // 每次新连接prover后sleep随机0-3秒,防止大量prover同时启动连接
                        let elapsed = thread_rng().next_u64() % 5000;
                        tokio::time::sleep(Duration::from_millis(elapsed)).await;

                        if let Some((block_height, coinbase_target, proof_target, epoch_hash)) = latest_state {
                            let request = PoolMessageSC::Notify(block_height as u64, proof_target, epoch_hash);
                            if let Err(error) = framed_write.send(request).await {
                                error!("[notify to client] {}", error);
                            } else {
                                //info!("send job to client block_height: {}, blockhash: {}", block_height, epoch_hash);
                                info!("new connection send_one_worker {}, {} {} {}", epoch_hash, coinbase_target, proof_target, block_height);
                            }
                        } else {
                            error!("Failed to retrieve block header or epoch hash");
                        }
                    }
                }
                _ => {
                    error!("invalid first message from client");
                    return Ok(());
                }
            };

            loop {
                let worker_ip = worker_ip.clone();
                let worker_name = worker_name.clone();
                let worker_address = worker_address.clone();
                let worker_version = worker_version.clone();
                tokio::select! {
                    // 1 分钟提交一次用户的solution信息
                    _= report_solution_ticker.tick() => {
                        let worker_solutions = worker_solutions.clone();
                        task::spawn(async move {
                            if !enable_report_solution {
                                return
                            }
                            // 取出solutions 并清空map
                            let solutions = {
                                let mut sns = worker_solutions.lock();
                                let ps:Vec<PoolSolution> = sns.clone().iter().map(|v|{
                                    v.1.clone()
                                }).collect();
                                sns.clear();
                                ps
                            };
                            if solutions.len() > 0 {
                                //let elapsed = thread_rng().next_u64() % 1000;
                                //tokio::time::sleep(Duration::from_millis(elapsed)).await;
                                match report_worker_solution(
                                    worker_ip.clone(),
                                    worker_name,
                                    worker_address,
                                    worker_version,
                                    solutions
                                ).await{
                                    Ok(v) =>{info!("report_worker_solution ok! worker_ip: {}", worker_ip)},
                                    Err(e) => {
                                        error!("report_worker_solution failed: {} worker_ip: {}", e.to_string(), worker_ip)
                                    }
                                }
                            } else {
                                info!("report_worker_solution skipped solution=0");
                            }
                        });
                    }

                    Ok(request) = server_handler.recv() =>{
                        match request {
                            ServerRequest::Notify(block_height, target, blockhash) => {
                                // 通知prover最新epoch， 在1秒内错峰推送epoch变化
                                let elapsed = thread_rng().next_u64() % 1000;
                                tokio::time::sleep(Duration::from_millis(elapsed)).await;
                                let message = PoolMessageSC::Notify(block_height, target, blockhash);
                                if let Err(error) = framed_write.send(message).await {
                                    error!("[notify to client] {}", error);
                                }
                            }

                            ServerRequest::Exit => {
                                let message = PoolMessageSC::ShutDown;
                                if let Err(error) = framed_write.send(message).await {
                                    error!("[send shutDown to client] {}", error);
                                }
                            }
                        }
                    }
                    result = framed_read.next() => match result {
                        Some(Ok(message)) => {
                            match message {
                                PoolMessageCS::Ping => {
                                    info!("received ping from client {}", ip_addr);
                                    // 更新peer连接时间
                                    self.set_peer(ip_addr.clone());
                                    //info!("active peers: {:?}", self.get_active_peers());
                                    let pong_message = PoolMessageSC::Pong;
                                    framed_write.send(pong_message).await?;
                                }

                                PoolMessageCS::Submit(worker_id, reserve, solution) => {
                                    // 更新peer连接时间
                                    self.set_peer(ip_addr.clone());
                                    let request = ClientRequest::Submit(worker_id, reserve, solution.clone());
                                    if let Err(error) = client_router.send(request).await {
                                        error!("[submit from work] {}", error);
                                    } else {
                                        debug!("received submit from client {}. worker_id:{} reserve:{}", ip_addr, worker_id, reserve);
                                    }
                                    if enable_report_solution {
                                        // 保存用户提交的所有solution便于计算share
                                        if let Ok(s) = solution.deserialize_blocking() {
                                            let network_target = self.latest_proof_target();
                                            worker_solutions.lock().insert(s.id().to_string(), PoolSolution{
                                                id: s.id().to_string(),
                                                epoch_hash: s.epoch_hash().to_string(),
                                                address: s.address().to_string(),
                                                counter: s.counter(),
                                                target: s.target(),
                                                job_target: network_target,
                                                network_target,
                                                timestamp: Local::now().timestamp(),
                                            });
                                        }
                                    }
                                }
                                // 收到prover上报hashRate, 保存到数据库
                                PoolMessageCS::ReportHashRate(worker_id, rate_1m, rate_5m, rate_15m, rate_30m, rate_60m) => {
                                    let hash_rates = vec![rate_1m, rate_5m, rate_15m, rate_30m, rate_60m];
                                    info!("received ReportHashRate: {:?} client: ({}){}", hash_rates, worker_address.clone(), worker_ip.clone());
                                    if enable_report_worker_log {
                                        task::spawn(async move {
                                            match report_worker_log(
                                                worker_ip.clone(),
                                                worker_name,
                                                worker_address,
                                                worker_version,
                                                hash_rates,
                                            ).await{
                                                Ok(v) =>{info!("report_worker_log ok! client: {}", worker_ip)},
                                                Err(e) => {
                                                    error!("report_worker_log failed: {} client: {}", e.to_string(), worker_ip)
                                                }
                                            }
                                        });
                                    }
                                }
                                PoolMessageCS::DisConnect(id) => {
                                    info!("client {} requested to disconnect", id);
                                    // 移除peer
                                    // self.remove_peer(ip_addr.clone());
                                    break;
                                }

                                _ => {
                                    warn!("Received unexpected message from client {}", ip_addr);
                                }
                            }
                        }

                        Some(Err(error)) => error!("failed to read message from client: {}", error),
                        None => {
                            error!("failed to read message from client: None");
                            break;
                        }
                    },
                }
            }
        }

        Ok(())
    }

    async fn dispatch_jobs(&self) -> Result<()> {
        let (router, handler) = oneshot::channel();
        let prover = self.clone();
        self.handles.lock().push(tokio::spawn(async move {
            let _ = router.send(());
            let mut current_epoch_number = 0;
            loop {
                let latest_state = prover
                    .latest_block_header
                    .read()
                    .as_ref()
                    .map(|header| (header.height(), header.coinbase_target(), header.proof_target()));
                // info!("step2");
                if let Some((block_height, coinbase_target, proof_target)) = latest_state {
                    let epoch_number = block_height / N::NUM_BLOCKS_PER_EPOCH;
                    if epoch_number > current_epoch_number {
                        current_epoch_number = epoch_number;
                        let latest_epoch_hash = *prover.latest_epoch_hash.read();
                        if let Some(epoch_hash) = latest_epoch_hash {
                            let request = ServerRequest::Notify(block_height as u64, proof_target, epoch_hash);
                            if let Err(error) = prover.server_router.send(request) {
                                error!("[send job to client] {}", error);
                            } else {
                                //info!("epoch changed, send new job to clients block_height={} block_height={} epoch_hash={}", block_height, proof_target, epoch_hash);
                                info!("epoch changed, send_all_workers count({}) {}, {} {} {}", prover.get_active_peers().len(), epoch_hash, coinbase_target, proof_target, epoch_number);
                            }
                        }
                    }
                }

                if prover.shutdown.load(Ordering::Relaxed) {
                    break;
                }

                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }));

        let _ = handler.await;

        Ok(())
    }

    async fn handle_clients_commit(&self, mut client_handler: ClientHandler<N>) -> Result<()> {
        let (router, handler) = oneshot::channel();

        let prover = self.clone();
        // 创建一个新任务来处理 client_handler
        self.handles.lock().push(tokio::spawn(async move {
            let _ = router.send(());

            loop {
                tokio::select! {
                    // 接收客户端请求
                    Some(request) = client_handler.recv() => {
                        match request {
                            ClientRequest::Submit(_work_id, reserve, prover_solution) => {
                                // 获取最新的 proof_target
                                if let Some(proof_target) = prover
                                    .latest_block_header
                                    .read()
                                    .as_ref()
                                    .map(|header| header.proof_target())
                                {
                                    // 处理 prover_solution
                                    if let Ok(solution) = prover_solution.deserialize_blocking() {
                                        if solution.target() >= proof_target {
                                            prover.broadcast_solution(solution);
                                            if reserve == 1 {
                                                info!("Found solution: {}", solution);
                                            }
                                        } else {
                                            // 处理无效的 solution
                                            if reserve == 1 {
                                                warn!(
                                                    "invalid solution received: {}, {} < {}",
                                                    solution,
                                                    solution.target(),
                                                    proof_target
                                                );
                                            }
                                        }
                                    }
                                } else {
                                    warn!("No valid proof target found in latest block header");
                                }
                            }
                            _ => {
                                // 处理其他类型的请求
                                warn!("Received an unhandled client request");
                            }
                        }
                    }

                    // 检查 shutdown 信号
                    _ = tokio::time::sleep(Duration::from_secs(1)), if prover.shutdown.load(Ordering::Relaxed) => {
                        info!("Shutting down client commit handler...");
                        break;
                    }
                }
            }
        }));

        let _ = handler.await;

        Ok(())
    }

    // 获取活跃的provers, (1分钟内有ping请求)
    fn get_active_peers(&self)->Vec<SocketAddr>{
        let mut ret = Vec::new();
        let values = self.peers.lock().clone();
        let now = Local::now().timestamp();
        for (addr, updated_secs )in values {
            if now - updated_secs < 360 {
                ret.push(addr)
            }
        }
        return ret
    }
    // 更新prover的活跃时间
    fn set_peer(&self, addr:SocketAddr){
        self.peers.lock().insert(addr, Local::now().timestamp());
    }
    fn remove_peer(&self, addr:SocketAddr){
        self.peers.lock().remove(&addr);
    }

    fn latest_proof_target(&self)->u64 {
        if let Some(proof_target) = self
            .latest_block_header
            .read()
            .as_ref()
            .map(|header| header.proof_target())
        {
            return proof_target;
        }
        return 0;
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct ReWorkerLog {
    worker_name: String,
    address: String,
    version: String,
    ip: String,
    rate_1m: u32,
    rate_5m: u32,
    rate_15m: u32,
    rate_30m: u32,
    rate_60m: u32,
    timestamp: i64,
}
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct PoolSolution {
    id:String,
    epoch_hash:String,
    address:String,
    counter:u64,
    target:u64,
    job_target:u64,
    network_target:u64,
    timestamp:i64
}
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct ReWorkerSolution {
    worker_name: String,
    address: String,
    version: String,
    ip: String,
    solution: PoolSolution,
}
fn reporter_api()->Result<String>{
    let url = std::env::var("ALEO_LOG_API").unwrap_or_default();
    if !url.starts_with("http") {
        return Err(anyhow::anyhow!("Read invalid value '{}' of env var 'ALEO_LOG_API'! (for example set 'ALEO_LOG_API=http://192.168.129.12:17777/api/v1')", url));
    }
    Ok(url)
}

// 上报机器信息 hash rate
async fn report_worker_log(ip:String, worker_name:String, address: String, version: String, hash_rates: Vec<u32> ) -> Result<bool> {
    if hash_rates.len() < 5 {
        return Err(anyhow::anyhow!("report_worker_log hash_rates len is not 5"));
    }
    let mut data = Vec::new();
    data.push(ReWorkerLog{
        worker_name,
        address,
        version,
        ip,
        rate_1m: hash_rates[0],
        rate_5m: hash_rates[1],
        rate_15m: hash_rates[2],
        rate_30m: hash_rates[3],
        rate_60m: hash_rates[4],
        timestamp: Local::now().timestamp(),
    });
    let data = serde_json::to_string(&data)?;

    let url = format!("{}{}", reporter_api()?, "/worker/log");
    // 创建 reqwest 的 Client 实例
    let client = reqwest::Client::new();
    // 准备要发送的 JSON 数据
    // 发送 HTTP POST 请求
    let resp = client.post(url.clone())
        .header("Content-Type", "application/json")
        .body(data.clone())
        .timeout(Duration::from_secs(3))
        .send().await?;
    let resp_status = resp.status().as_u16();
    let resp_body = resp.text().await?;
    if resp_status != 200 {
        error!("report_worker_log POST failed! url: {} data: {}, response http-status: {} body: {}", url.clone(), data.clone(), resp_status, resp_body.clone());
        return Err(anyhow::anyhow!("report_worker_log POST response http-status is not 200"));
    }
    debug!("report_worker_log POST success! url: {} data: {} response body: {}", url, data, resp_body);
    Ok(true)
}

// 上报 solution
async fn report_worker_solution(ip:String, worker_name:String, address: String, version: String, solutions: Vec<PoolSolution>) -> Result<bool> {
    let mut data = Vec::new();
    for v in solutions {
        data.push(ReWorkerSolution{
            worker_name:worker_name.clone(),
            address: address.clone(),
            version: version.clone(),
            ip: ip.clone(),
            solution: v,
        });
    }
    let data = serde_json::to_string(&data)?;
    let url = format!("{}{}", reporter_api()?, "/worker/solution");
    // 创建 reqwest 的 Client 实例
    let client = reqwest::Client::new();
    // 准备要发送的 JSON 数据
    // 发送 HTTP POST 请求
    let resp = client.post(url.clone())
        .header("Content-Type", "application/json")
        .body(data.clone())
        .timeout(Duration::from_secs(3))
        .send().await?;
    let resp_status = resp.status().as_u16();
    let resp_body = resp.text().await?;
    if resp_status != 200 {
        error!("report_worker_solution POST failed! url: {} data: {}, response http-status: {} body: {}", url.clone(), data.clone(), resp_status, resp_body.clone());
        return Err(anyhow::anyhow!("report_worker_solution POST response http-status is not 200"));
    }
    debug!("report_worker_solution POST success! url: {} data: {} response body: {}", url, data, resp_body);
    Ok(true)
}