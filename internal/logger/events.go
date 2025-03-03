package log

const (
	EventReasonAddedOrUpdated            = "AddedOrUpdated"            //nolint:revive
	EventReasonAddedOrUpdatedWithError   = "AddedOrUpdatedWithError"   //nolint:revive
	EventReasonAddedOrUpdatedWithWarning = "AddedOrUpdatedWithWarning" //nolint:revive
	EventReasonBadConfig                 = "BadConfig"                 //nolint:revive
	EventReasonCreateDNSEndpoint         = "CreateDNSEndpoint"         //nolint:revive
	EventReasonCreateCertificate         = "CreateCertificate"         //nolint:revive
	EventReasonDeleteCertificate         = "DeleteCertificate"         //nolint:revive
	EventReasonIgnored                   = "Ignored"                   //nolint:revive
	EventReasonInvalidValue              = "InvalidValue"              //nolint:revive
	EventReasonLicenseExpiry             = "LicenseExpiry"             //nolint:revive
	EventReasonNoIngressMasterFound      = "NoIngressMasterFound"      //nolint:revive
	EventReasonNoVirtualServerFound      = "NoVirtualServerFound"      //nolint:revive
	EventReasonRejected                  = "Rejected"                  //nolint:revive
	EventReasonRejectedWithError         = "RejectedWithError"         //nolint:revive
	EventReasonSecretDeleted             = "SecretDeleted"             //nolint:revive
	EventReasonSecretUpdated             = "SecretUpdated"             //nolint:revive
	EventReasonUpdated                   = "Updated"                   //nolint:revive
	EventReasonUpdatedWithError          = "UpdatedWithError"          //nolint:revive
	EventReasonUpdateCertificate         = "UpdateCertificate"         //nolint:revive
	EventReasonUpdateDNSEndpoint         = "UpdateDNSEndpoint"         //nolint:revive
	EventReasonUpdatePodLabel            = "UpdatePodLabel"            //nolint:revive
	EventReasonUsageGraceEnding          = "UsageGraceEnding"          //nolint:revive
	EventReasonServiceFailedToCreate     = "ServiceFailedToCreate"     //nolint:revive
)
