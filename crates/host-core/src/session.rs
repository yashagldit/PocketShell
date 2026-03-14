use crate::error::Result;
use crate::models::SessionRequest;
use crate::pty::SessionManager;

pub fn accept_session(
    manager: &mut SessionManager,
    req: &SessionRequest,
    shell: &str,
) -> Result<()> {
    if let Some(target) = &req.attach_target {
        manager.create_attached_session(
            req.session_id.clone(),
            &target.session_type,
            &target.name,
            req.cols,
            req.rows,
        )
    } else {
        manager.create_session(req.session_id.clone(), shell, req.cols, req.rows)
    }
}
