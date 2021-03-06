// Author(s): Michael Koeppl

package jenkinsrole

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// Client implements functionality for manipulating roles in Jenkins.
type Client struct {
	// The Jenkins hostname
	HostName string
	// The user used to manipulate roles
	User string
	// The token for the given user
	Token string
}

func hostnameHasCorrectPrefix(hostname string) bool {
	return strings.HasPrefix(hostname, "http://") || strings.HasPrefix(hostname, "https://")
}

// NewClient creates a new instance of Client and does additional checks to
// ensure that all attributes are valid.
func NewClient(hostname, user, token string) (*Client, error) {
	if !hostnameHasCorrectPrefix(hostname) {
		return nil, errors.New("Hostname has incorrect prefix ('https://' or 'http://' required)")
	}
	hostname = strings.TrimSuffix(hostname, "/")
	return &Client{
		HostName: hostname,
		User:     user,
		Token:    token,
	}, nil
}

// performRequest creates a request, attaches the basic authentication header
// to it and sends the request off.
func (c *Client) performRequest(method, url string, body *bytes.Reader) (*http.Response, error) {
	var req *http.Request
	var err error
	if body == nil {
		req, err = http.NewRequest(method, url, nil)
	} else {
		req, err = http.NewRequest(method, url, body)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}
	if err != nil {
		return nil, err
	}
	attachAuthHeader(req, c.User, c.Token)

	hc := &http.Client{}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// AddRole adds a role to the role map.
// See https://github.com/runzexia/role-strategy-plugin/blob/5fdea531bc5aff5865a64cead6abcf9461720b1b/src/main/java/com/michelin/cio/hudson/plugins/rolestrategy/RoleBasedAuthorizationStrategy.java#L233
func (c *Client) AddRole(roleType, roleName string, permissions []Permission, overwrite bool, pattern ...string) error {
	targetURL := fmt.Sprintf("%s/role-strategy/strategy/addRole", c.HostName)

	var permStrings []string
	// If the package user added the 'All' permission to the list of
	// permissions for the new role, we just add all available permissions
	// (just use the pre-defined list).
	if (len(permissions) == 1 && permissions[0] == All) || permListContainsAllPermission(permissions) {
		permStrings = permissionStrings
	} else {
		permStrings = make([]string, len(permissions))
		for i, p := range permissions {
			permStrings[i] = p.getPermissionString()
		}
	}

	bodyStr := fmt.Sprintf(
		"type=%s&roleName=%s&permissionIds=%s&overwrite=%t",
		roleType,
		roleName,
		strings.Join(permStrings, ","),
		overwrite,
	)
	if len(pattern) >= 1 && pattern[0] != "" {
		bodyStr += fmt.Sprintf("&pattern=%s", pattern[0])
	}

	body := bytes.NewReader([]byte(bodyStr))

	resp, err := c.performRequest(http.MethodPost, targetURL, body)
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	default:
		defer resp.Body.Close()
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return errors.New(string(respBody))
	}
}

// RemoveRoles removes one or multiple roles with the given names.
// https://github.com/runzexia/role-strategy-plugin/blob/5fdea531bc5aff5865a64cead6abcf9461720b1b/src/main/java/com/michelin/cio/hudson/plugins/rolestrategy/RoleBasedAuthorizationStrategy.java#L363
func (c *Client) RemoveRoles(roleType string, roleNames []string) error {
	targetURL := fmt.Sprintf("%s/role-strategy/strategy/removeRoles", c.HostName)
	body := bytes.NewReader([]byte(
		fmt.Sprintf("type=%s&roleNames=%s",
			roleType,
			strings.Join(roleNames, ","),
		),
	))

	resp, err := c.performRequest(http.MethodPost, targetURL, body)
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	default:
		defer resp.Body.Close()
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return errors.New(string(respBody))
	}
}

// AssignRole assigns the role with the given name to the user with the given
// SID.
// https://github.com/runzexia/role-strategy-plugin/blob/5fdea531bc5aff5865a64cead6abcf9461720b1b/src/main/java/com/michelin/cio/hudson/plugins/rolestrategy/RoleBasedAuthorizationStrategy.java#L393
func (c *Client) AssignRole(roleType, roleName, sid string) error {
	targetURL := fmt.Sprintf("%s/role-strategy/strategy/assignRole", c.HostName)
	body := bytes.NewReader([]byte(
		fmt.Sprintf("type=%s&roleName=%s&sid=%s",
			roleType,
			roleName,
			sid,
		),
	))

	resp, err := c.performRequest(http.MethodPost, targetURL, body)
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	default:
		defer resp.Body.Close()
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return errors.New(string(respBody))
	}
}

// UnassignRole unassigns the role with the given name from the user with the
// given SID.
// https://github.com/runzexia/role-strategy-plugin/blob/5fdea531bc5aff5865a64cead6abcf9461720b1b/src/main/java/com/michelin/cio/hudson/plugins/rolestrategy/RoleBasedAuthorizationStrategy.java#L453
func (c *Client) UnassignRole(roleType, roleName, sid string) error {
	targetURL := fmt.Sprintf("%s/role-strategy/strategy/unassignRole", c.HostName)
	body := bytes.NewReader([]byte(
		fmt.Sprintf("type=%s&roleName=%s&sid=%s",
			roleType,
			roleName,
			sid,
		),
	))

	resp, err := c.performRequest(http.MethodPost, targetURL, body)
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	default:
		defer resp.Body.Close()
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return errors.New(string(respBody))
	}
}

// DeleteSID deletes an SID from all granted roles.
// https://github.com/runzexia/role-strategy-plugin/blob/5fdea531bc5aff5865a64cead6abcf9461720b1b/src/main/java/com/michelin/cio/hudson/plugins/rolestrategy/RoleBasedAuthorizationStrategy.java#L431
func (c *Client) DeleteSID(roleType, sid string) error {
	targetURL := fmt.Sprintf("%s/role-strategy/strategy/deleteSid", c.HostName)
	body := bytes.NewReader([]byte(
		fmt.Sprintf("type=%s&sid=%s",
			roleType,
			sid,
		),
	))

	resp, err := c.performRequest(http.MethodPost, targetURL, body)
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	default:
		defer resp.Body.Close()
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return errors.New(string(respBody))
	}
}

// GetRole gets the role with the given role name.
// https://github.com/runzexia/role-strategy-plugin/blob/5fdea531bc5aff5865a64cead6abcf9461720b1b/src/main/java/com/michelin/cio/hudson/plugins/rolestrategy/RoleBasedAuthorizationStrategy.java#L324
func (c *Client) GetRole(roleType, roleName string) (*Role, error) {
	targetURL := fmt.Sprintf("%s/role-strategy/strategy/getRole?type=%s&roleName=%s",
		c.HostName,
		roleType,
		roleName,
	)

	resp, err := c.performRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		r := &Role{}
		if err := json.Unmarshal(respBody, r); err != nil {
			return nil, err
		}
		return r, nil
	default:
		return nil, errors.New(string(respBody))
	}
}

// GetAllRoles gets a list of all roles with all users they're assigned to.
func (c *Client) GetAllRoles(roleType string) (RolesWithUsers, error) {
	targetURL := fmt.Sprintf("%s/role-strategy/strategy/getAllRoles?type=%s", c.HostName, roleType)

	resp, err := c.performRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		rwu := make(map[string][]string)
		if err := json.Unmarshal(respBody, &rwu); err != nil {
			return nil, err
		}
		return rwu, nil
	default:
		return nil, errors.New(string(respBody))
	}
}
