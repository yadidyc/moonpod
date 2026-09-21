///|
pub extend PolicyJsonError with @debug.Debug::{to_repr}

///|
pub extend PolicyJsonError with Eq::{not_equal, equal}

///|
pub extend OperationJsonError with @debug.Debug::{to_repr}

///|
pub extend OperationJsonError with Eq::{not_equal, equal}

///|
pub extend Operation with @debug.Debug::{to_repr}

///|
pub extend Operation with Eq::{not_equal, equal}

///|
pub extend NetworkRule with @debug.Debug::{to_repr}

///|
pub extend NetworkRule with Eq::{not_equal, equal}

///|
pub extend CommandRule with @debug.Debug::{to_repr}

///|
pub extend CommandRule with Eq::{not_equal, equal}

///|
pub extend ToolQuota with @debug.Debug::{to_repr}

///|
pub extend ToolQuota with Eq::{not_equal, equal}

///|
pub extend SessionState with @debug.Debug::{to_repr}

///|
pub extend SessionState with Eq::{not_equal, equal}

///|
pub extend DenyReason with @debug.Debug::{to_repr}

///|
pub extend DenyReason with Eq::{not_equal, equal}

///|
pub extend Decision with @debug.Debug::{to_repr}

///|
pub extend Decision with Eq::{not_equal, equal}

///|
pub extend ApprovalRequest with @debug.Debug::{to_repr}

///|
pub extend ApprovalRequest with Eq::{not_equal, equal}

///|
pub extend AuditEvent with @debug.Debug::{to_repr}

///|
pub extend AuditEvent with Eq::{not_equal, equal}

///|
pub extend PolicyConfigError with @debug.Debug::{to_repr}

///|
pub extend PolicyConfigError with Eq::{not_equal, equal}

///|
pub extend ResourceRule with @debug.Debug::{to_repr}

///|
pub extend ResourceRule with Eq::{not_equal, equal}
