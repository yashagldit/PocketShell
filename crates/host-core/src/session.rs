use crate::error::Result;
use crate::models::SessionRequest;
use crate::pty::SessionManager;

pub fn accept_session(
    manager: &mut SessionManager,
    req: &SessionRequest,
    shell: &str,
) -> Result<()> {
    manager.create_session(req.session_id.clone(), shell, req.cols, req.rows)
}
