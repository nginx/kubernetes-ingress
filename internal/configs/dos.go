package configs

// appProtectDosResource holds the file names of APDosPolicy and APDosLogConf resources used in an Ingress resource.
type appProtectDosResource struct {
	AppProtectDosEnable          string
	AppProtectDosLogEnable       bool
	AppProtectDosMonitorURI      string
	AppProtectDosMonitorProtocol string
	AppProtectDosMonitorTimeout  uint64
	AppProtectDosName            string
	AppProtectDosAccessLogDst    string
	AppProtectDosPolicyFile      string
	AppProtectDosLogConfFile     string
	AppProtectDosAllowListPath   string
}

func getAppProtectDosResource(dosEx *DosEx) *appProtectDosResource {
	var dosResource appProtectDosResource
	if dosEx == nil || dosEx.DosProtected == nil {
		return nil
	}

	protected := dosEx.DosProtected
	dosResource.AppProtectDosEnable = "off"
	if protected.Spec.Enable {
		dosResource.AppProtectDosEnable = "on"
	}
	dosResource.AppProtectDosName = protected.Namespace + "/" + protected.Name + "/" + protected.Spec.Name

	if protected.Spec.AllowList != nil {
		dosResource.AppProtectDosAllowListPath = appProtectDosAllowListFileName(protected.Namespace, protected.Name)
	}

	if protected.Spec.ApDosMonitor != nil {
		dosResource.AppProtectDosMonitorURI = protected.Spec.ApDosMonitor.URI
		dosResource.AppProtectDosMonitorProtocol = protected.Spec.ApDosMonitor.Protocol
		dosResource.AppProtectDosMonitorTimeout = protected.Spec.ApDosMonitor.Timeout
	}

	if protected.Spec.DosAccessLogDest != "" {
		dosResource.AppProtectDosAccessLogDst = generateDosLogDest(protected.Spec.DosAccessLogDest)
	}

	if dosEx.DosPolicy != nil {
		dosResource.AppProtectDosPolicyFile = appProtectDosPolicyFileName(dosEx.DosPolicy.GetNamespace(), dosEx.DosPolicy.GetName())
	}

	if dosEx.DosLogConf != nil {
		log := dosEx.DosLogConf
		logConfFileName := appProtectDosLogConfFileName(log.GetNamespace(), log.GetName())
		dosResource.AppProtectDosLogConfFile = logConfFileName + " " + generateDosLogDest(protected.Spec.DosSecurityLog.DosLogDest)
		dosResource.AppProtectDosLogEnable = protected.Spec.DosSecurityLog.Enable
	}

	return &dosResource
}
