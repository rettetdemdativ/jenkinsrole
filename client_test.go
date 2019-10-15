// Author(s): Michael Koeppl

package jenkinsrole_test

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/calmandniceperson/jenkinsrole"
	"github.com/stretchr/testify/assert"
)

const (
	jenkinsUser  = "admin"
	jenkinsToken = "testToken"
)

func checkValidHeader(req *http.Request) int {
	const expectedHeaderPrefix = "Basic "
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, expectedHeaderPrefix) {
		return http.StatusBadRequest
	}

	sb, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, expectedHeaderPrefix))
	if err != nil {
		return http.StatusBadRequest
	}

	if len(strings.Split(string(sb), ":")[0]) == 0 || len(strings.Split(string(sb), ":")[1]) == 0 {
		return http.StatusBadRequest
	}
	return http.StatusOK
}

// addRoleHandler is a mock handler function used by httptest to test the
// AddRole functionality.
func addRoleHandler(res http.ResponseWriter, req *http.Request) {

}

func TestAddRole(t *testing.T) {
	const (
		roleType      = "globalRole"
		roleName      = "admin-role"
		permissionIDs = "hudson.model.Item.Discover,hudson.model.Item.ExtendedRead"
		overwrite     = "true"
	)

	testCases := []struct {
		name string

		headerUser    string
		headerToken   string
		roleType      string
		roleName      string
		permissionIDs string
		overwrite     string

		expectError bool
	}{
		{"valid", jenkinsUser, jenkinsToken, roleType, roleName, permissionIDs, overwrite, false},
		{"invalid header", "", "", roleType, roleName, permissionIDs, overwrite, true},
		{"body_missing_param", jenkinsUser, jenkinsToken, "", roleName, permissionIDs, overwrite, true},
	}

	testServer := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		headerCode := checkValidHeader(req)
		if headerCode != http.StatusOK {
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte("Invalid header"))
			return
		}

		defer req.Body.Close()
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(err.Error()))
			return
		}

		params, err := url.ParseQuery(string(body))
		if err != nil {
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(err.Error()))
			return
		}

		if params.Get("type") == "" ||
			params.Get("roleName") == "" ||
			params.Get("permissionIds") == "" ||
			params.Get("overwrite") == "" {
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte("Missing query param"))
			return
		}
	}))
	defer testServer.Close()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := jenkinsrole.Client{
				HostName: testServer.URL,
				User:     tc.headerUser,
				Token:    tc.headerToken,
			}

			err := c.AddRole(tc.roleType, tc.roleName, []string{tc.permissionIDs}, tc.overwrite)

			if !tc.expectError {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestRemoveRoles(t *testing.T) {
	const (
		defaultRoleType = "globalRoles"
	)

	testCases := []struct {
		name string

		headerUser  string
		headerToken string
		roleType    string
		roleNames   []string

		hasError bool
	}{
		{"valid", jenkinsUser, jenkinsToken, defaultRoleType, []string{"admin", "testRole1", "testRole2"}, false},
		{"invalid_header", jenkinsUser, "", defaultRoleType, []string{"admin", "testRole1", "testRole2"}, true},
		{"no_role_names", jenkinsUser, jenkinsToken, defaultRoleType, []string{}, true},
	}

	testServer := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		headerCode := checkValidHeader(req)
		if headerCode != http.StatusOK {
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte("Invalid header"))
			return
		}

		defer req.Body.Close()
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(err.Error()))
			return
		}

		params, err := url.ParseQuery(string(body))
		if err != nil {
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(err.Error()))
			return
		}

		if params.Get("type") == "" || params.Get("roleNames") == "" {
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte("Missing query param"))
			return
		}

	}))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := jenkinsrole.Client{
				HostName: testServer.URL,
				User:     tc.headerUser,
				Token:    tc.headerToken,
			}

			err := c.RemoveRoles(tc.roleType, tc.roleNames)

			if !tc.hasError {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestGetRole(t *testing.T) {
	const (
		roleType = "globalRoles"
		roleName = "admin"
	)

	permissionIDs := map[string]bool{
		"testPermission1": true,
		"testPermission2": false,
		"testPermission3": true,
	}

	sids := []string{"admin"}

	testServer := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		headerCode := checkValidHeader(req)
		if headerCode != http.StatusOK {
			resp.WriteHeader(headerCode)
			resp.Write([]byte("Invalid header"))
			return
		}

		typeQueryParam := req.URL.Query().Get("type")
		roleNameQueryParam := req.URL.Query().Get("roleName")

		if typeQueryParam == "" || roleNameQueryParam == "" {
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte("Missing query param"))
			return
		}

		r := &jenkinsrole.Role{
			PermissionIDs: permissionIDs,
			SIDs:          sids,
		}

		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(http.StatusOK)
		json.NewEncoder(resp).Encode(r)
	}))
	defer testServer.Close()

	testCases := []struct {
		name string

		headerUser  string
		headerToken string
		roleType    string
		roleName    string

		expectError bool
	}{
		{"valid", jenkinsUser, jenkinsToken, roleType, roleName, false},
		{"invalid", "", "", roleType, roleName, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := &jenkinsrole.Client{
				HostName: testServer.URL,
				User:     tc.headerUser,
				Token:    tc.headerToken,
			}

			role, err := c.GetRole(tc.roleType, roleName)

			if !tc.expectError {
				assert.NoError(t, err)
				assert.NotNil(t, role)
				assert.NotEmpty(t, role)

				assert.EqualValues(t, role.SIDs, sids)
				assert.EqualValues(t, role.PermissionIDs, permissionIDs)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
