// Author(s): Michael Koeppl

package jenkinsrole

// Permission repesents a permission that can be assigned to a role.
type Permission int

const (
	// ViewDeletePermission = hudson.model.View.Delete
	ViewDeletePermission Permission = iota
	// ComputerConnectPermission = hudson.model.Computer.Connect
	ComputerConnectPermission
	// RunDeletePermission = hudson.model.Run.Delete
	RunDeletePermission
	// CredentialsProviderManageDomainsPermission = com.cloudbees.plugins.credentials.CredentialsProvider.ManageDomains
	CredentialsProviderManageDomainsPermission
	// ComputerCreatePermission = hudson.model.Computer.Create
	ComputerCreatePermission
	// ViewConfigurePermission = hudson.model.View.Configure
	ViewConfigurePermission
	// ComputerBuildPermission = hudson.model.Computer.Build
	ComputerBuildPermission
	// ItemConfigurePermission = hudson.model.Item.Configure
	ItemConfigurePermission
	// HudsonAdministerPermission = hudson.model.Hudson.Administer
	HudsonAdministerPermission
	// ItemCancelPermission = hudson.model.Item.Cancel
	ItemCancelPermission
	// ItemReadPermission = hudson.model.Item.Read
	ItemReadPermission
	// CredentialsProviderViewPermission = com.cloudbees.plugins.credentials.CredentialsProvider.View
	CredentialsProviderViewPermission
	// ComputerDeletePermission = hudson.model.Computer.Delete
	ComputerDeletePermission
	// ItemBuildPermission = hudson.model.Item.Build
	ItemBuildPermission
	// LockableResourcesManagerUnlockPermission = org.jenkins.plugins.lockableresources.LockableResourcesManager.Unlock
	LockableResourcesManagerUnlockPermission
	// SCMTagPermission = hudson.scm.SCM.Tag
	SCMTagPermission
	// ItemMovePermission = hudson.model.Item.Move
	ItemMovePermission
	// ItemDiscoverPermission = hudson.model.Item.Discover
	ItemDiscoverPermission
	// HudsonReadPermission = hudson.model.Hudson.Read
	HudsonReadPermission
	// CredentialsProviderUpdatePermission = com.cloudbees.plugins.credentials.CredentialsProvider.Update
	CredentialsProviderUpdatePermission
	// ItemCreatePermission = hudson.model.Item.Create
	ItemCreatePermission
	// ItemWorkspacePermission = hudson.model.Item.Workspace
	ItemWorkspacePermission
	// CredentialsProviderDeletePermission = com.cloudbees.plugins.credentials.CredentialsProvider.Delete
	CredentialsProviderDeletePermission
	// ComputerProvisionPermission = hudson.model.Computer.Provision
	ComputerProvisionPermission
	// RunReplayPermission = hudson.model.Run.Replay
	RunReplayPermission
	// ViewReadPermission = hudson.model.View.Read
	ViewReadPermission
	// LockableResourcesManagerViewPermission = org.jenkins.plugins.lockableresources.LockableResourcesManager.View
	LockableResourcesManagerViewPermission
	// ViewCreatePermission = hudson.model.View.Create
	ViewCreatePermission
	// ItemDeletePermission = hudson.model.Item.Delete
	ItemDeletePermission
	// ComputerConfigurePermission = hudson.model.Computer.Configure
	ComputerConfigurePermission
	// CredentialsProviderCreatePermission = com.cloudbees.plugins.credentials.CredentialsProvider.Create
	CredentialsProviderCreatePermission
	// ComputerDisconnectPermission = hudson.model.Computer.Disconnect
	ComputerDisconnectPermission
	// LockableResourcesManagerReservePermission = org.jenkins.plugins.lockableresources.LockableResourcesManager.Reserve
	LockableResourcesManagerReservePermission
	// RunUpdatePermission = hudson.model.Run.Update
	RunUpdatePermission

	// All activates all permissions for a role.
	All
)

func permListContainsAllPermission(permList []Permission) bool {
	for _, p := range permList {
		if p == All {
			return true
		}
	}
	return false
}

func (p Permission) getPermissionString() string {
	return permissionStrings[p]
}

var permissionStrings = []string{
	"hudson.model.View.Delete",
	"hudson.model.Computer.Connect",
	"hudson.model.Run.Delete",
	"com.cloudbees.plugins.credentials.CredentialsProvider.ManageDomains",
	"hudson.model.Computer.Create",
	"hudson.model.View.Configure",
	"hudson.model.Computer.Build",
	"hudson.model.Item.Configure",
	"hudson.model.Hudson.Administer",
	"hudson.model.Item.Cancel",
	"hudson.model.Item.Read",
	"com.cloudbees.plugins.credentials.CredentialsProvider.View",
	"hudson.model.Computer.Delete",
	"hudson.model.Item.Build",
	"org.jenkins.plugins.lockableresources.LockableResourcesManager.Unlock",
	"hudson.scm.SCM.Tag",
	"hudson.model.Item.Move",
	"hudson.model.Item.Discover",
	"hudson.model.Hudson.Read",
	"com.cloudbees.plugins.credentials.CredentialsProvider.Update",
	"hudson.model.Item.Create",
	"hudson.model.Item.Workspace",
	"com.cloudbees.plugins.credentials.CredentialsProvider.Delete",
	"hudson.model.Computer.Provision",
	"hudson.model.Run.Replay",
	"hudson.model.View.Read",
	"org.jenkins.plugins.lockableresources.LockableResourcesManager.View",
	"hudson.model.View.Create",
	"hudson.model.Item.Delete",
	"hudson.model.Computer.Configure",
	"com.cloudbees.plugins.credentials.CredentialsProvider.Create",
	"hudson.model.Computer.Disconnect",
	"org.jenkins.plugins.lockableresources.LockableResourcesManager.Reserve",
	"hudson.model.Run.Update",
}
