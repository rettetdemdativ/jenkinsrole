// Author(s): Michael Koeppl

package jenkinsrole

// RolesWithUsers represents the response of the getAllRoles route.
type RolesWithUsers map[string][]string

// Role represents a role as it is implemented in the Role Strategy plugin.
// https://github.com/runzexia/role-strategy-plugin/blob/master/src/main/java/com/michelin/cio/hudson/plugins/rolestrategy/Role.java
type Role struct {
	PermissionIDs map[string]bool
	SIDs          []string
}
