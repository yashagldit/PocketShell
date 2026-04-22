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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::HostError;
    use crate::models::AttachTarget;
    use crate::pty::SessionManager;

    fn make_req(session_id: &str, attach: Option<AttachTarget>) -> SessionRequest {
        SessionRequest {
            session_id: session_id.to_string(),
            mobile_device_id: "mobile-1".to_string(),
            cols: 80,
            rows: 24,
            attach_target: attach,
        }
    }

    #[test]
    fn accept_session_routes_to_create_attached_session_for_unsupported_type() {
        let mut mgr = SessionManager::new(4);
        let req = make_req(
            "s1",
            Some(AttachTarget {
                session_type: "nope".to_string(),
                name: "foo".to_string(),
            }),
        );
        // Dispatch should go to create_attached_session, which rejects unknown types.
        let err = accept_session(&mut mgr, &req, "/bin/sh").unwrap_err();
        match err {
            HostError::Pty(msg) => assert!(
                msg.contains("unsupported session type"),
                "unexpected msg: {msg}"
            ),
            other => panic!("expected Pty error, got {other:?}"),
        }
        // No session should be registered.
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn accept_session_rejects_invalid_attach_name_for_tmux() {
        let mut mgr = SessionManager::new(4);
        let req = make_req(
            "s2",
            Some(AttachTarget {
                session_type: "tmux".to_string(),
                // Contains a shell metacharacter to trigger validate_session_name.
                name: "bad;name".to_string(),
            }),
        );
        let err = accept_session(&mut mgr, &req, "/bin/sh").unwrap_err();
        match err {
            HostError::Pty(msg) => assert!(
                msg.contains("invalid characters") || msg.contains("invalid session name"),
                "unexpected msg: {msg}"
            ),
            other => panic!("expected Pty error, got {other:?}"),
        }
    }

    #[test]
    fn accept_session_routes_to_create_session_when_no_attach_target() {
        let mut mgr = SessionManager::new(4);
        let req = make_req("s3", None);
        // A non-existent shell should fail in spawn inside create_session — proving
        // we routed to the shell-spawning path, not the attach path.
        let err = accept_session(
            &mut mgr,
            &req,
            "/definitely/does/not/exist/pocketshell_test_shell",
        )
        .unwrap_err();
        match err {
            HostError::Pty(msg) => assert!(
                msg.contains("spawn shell failed") || msg.contains("openpty"),
                "unexpected msg: {msg}"
            ),
            other => panic!("expected Pty error, got {other:?}"),
        }
        assert_eq!(mgr.active_count(), 0);
    }
}
