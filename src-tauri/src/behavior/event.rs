#[derive(Debug, Clone)]
pub struct SystemEvent {
    pub event_type: EventType,
    pub context: EventContext,
    pub timestamp: Instant,
    pub process_info: ProcessInfo,
    pub resource_info: Option<ResourceInfo>,
}

#[derive(Debug, Clone)]
pub enum EventType {
    ProcessStart(ProcessStartEvent),
    ProcessExit(ProcessExitEvent),
    FileAccess(FileAccessEvent),
    NetworkConnection(NetworkEvent),
    SystemCall(SyscallEvent),
    PrivilegeEscalation(PrivilegeEvent),
    ResourceUsage(ResourceEvent),
}

#[derive(Debug, Clone)]
pub struct EventContext {
    pub user_id: u32,
    pub group_id: u32,
    pub parent_process: Option<ProcessInfo>,
    pub environment: HashMap<String, String>,
    pub security_context: SecurityContext,
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct SecurityContext {
    pub selinux_context: Option<String>,
    pub capabilities: Vec<String>,
    pub namespaces: Vec<String>,
    pub cgroup_path: String,
}
