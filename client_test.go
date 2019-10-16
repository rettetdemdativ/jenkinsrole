// Author(s): Michael Koeppl

package jenkinsrole_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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

func TestAddRole(t *testing.T) {
	const (
		roleType  = "globalRole"
		roleName  = "admin-role"
		overwrite = "true"
	)

	defaultPermissionList := []jenkinsrole.Permission{
		jenkinsrole.ItemReadPermission, jenkinsrole.ComputerBuildPermission,
	}

	testCases := []struct {
		name string

		headerUser  string
		headerToken string
		roleType    string
		roleName    string
		permissions []jenkinsrole.Permission
		overwrite   string

		expectError bool
	}{
		{"valid", jenkinsUser, jenkinsToken, roleType, roleName, defaultPermissionList, overwrite, false},
		{"invalid header", "", "", roleType, roleName, defaultPermissionList, overwrite, true},
		{"body_missing_param", jenkinsUser, jenkinsToken, "", roleName, defaultPermissionList, overwrite, true},
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

			err := c.AddRole(tc.roleType, tc.roleName, tc.permissions, tc.overwrite)

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

func TestAssignRole(t *testing.T) {
	const (
		roleType = "globalRoles"
		roleName = "testRole"
		sid      = "sid1"
	)

	testCases := []struct {
		name string

		headerUser  string
		headerToken string
		roleType    string
		roleName    string
		sid         string

		expectError bool
	}{
		{"valid", jenkinsUser, jenkinsToken, roleType, roleName, sid, false},
		{"invalid_header", jenkinsUser, "", roleType, roleName, sid, true},
		{"incomplete_body", jenkinsUser, jenkinsToken, roleType, "", sid, true},
	}

	testServer := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		headerCode := checkValidHeader(req)
		if headerCode != http.StatusOK {
			resp.WriteHeader(headerCode)
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

		if params.Get("type") == "" || params.Get("roleName") == "" || params.Get("sid") == "" {
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

			err := c.AssignRole(tc.roleType, tc.roleName, tc.sid)

			if !tc.expectError {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestUnassignRole(t *testing.T) {
	const (
		roleType = "globalRoles"
		roleName = "testRole"
		sid      = "sid1"
	)

	testCases := []struct {
		name string

		headerUser  string
		headerToken string
		roleType    string
		roleName    string
		sid         string

		expectError bool
	}{
		{"valid", jenkinsUser, jenkinsToken, roleType, roleName, sid, false},
		{"invalid_header", jenkinsUser, "", roleType, roleName, sid, true},
		{"incomplete_body", jenkinsUser, jenkinsToken, roleType, "", sid, true},
	}

	testServer := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		headerCode := checkValidHeader(req)
		if headerCode != http.StatusOK {
			resp.WriteHeader(headerCode)
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

		if params.Get("type") == "" || params.Get("roleName") == "" || params.Get("sid") == "" {
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

			err := c.UnassignRole(tc.roleType, tc.roleName, tc.sid)

			if !tc.expectError {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestDeleteSID(t *testing.T) {
	const (
		roleType = "globalRoles"
		sid      = "sid1"
	)

	testCases := []struct {
		name string

		headerUser  string
		headerToken string
		roleType    string
		sid         string

		expectError bool
	}{
		{"valid", jenkinsUser, jenkinsToken, roleType, sid, false},
		{"invalid_header", jenkinsUser, "", roleType, sid, true},
		{"incomplete_body", jenkinsUser, jenkinsToken, "", sid, true},
	}

	testServer := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		headerCode := checkValidHeader(req)
		if headerCode != http.StatusOK {
			resp.WriteHeader(headerCode)
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

		if params.Get("type") == "" || params.Get("sid") == "" {
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

			err := c.DeleteSID(tc.roleType, tc.sid)

			if !tc.expectError {
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

func TestGetAllRoles(t *testing.T) {
	rwu := jenkinsrole.RolesWithUsers{
		"admin":    []string{"sid1", "sid2", "sid3"},
		"testrole": []string{},
	}
	rolesMap := map[string]jenkinsrole.RolesWithUsers{
		"globalRoles":  rwu,
		"projectRoles": make(jenkinsrole.RolesWithUsers),
	}

	testCases := []struct {
		name string

		headerUser     string
		headerToken    string
		roleType       string
		rolesWithUsers jenkinsrole.RolesWithUsers

		expectError bool
	}{
		{"valid", jenkinsUser, jenkinsToken, "globalRoles", rolesMap["globalRoles"], false},
		{"empty_map", jenkinsUser, jenkinsToken, "projectRoles", rolesMap["projectRoles"], false},
		{"invalid_header", jenkinsUser, "", "globalRoles", rolesMap["globalRoles"], true},
	}

	testServer := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		headerCode := checkValidHeader(req)
		if headerCode != http.StatusOK {
			resp.WriteHeader(headerCode)
			resp.Write([]byte("Invalid header"))
			return
		}

		if req.URL.Query().Get("type") == "" {
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte("Missing query param"))
			return
		}

		if _, ok := rolesMap[req.URL.Query().Get("type")]; !ok {
			resp.WriteHeader(http.StatusInternalServerError)
			resp.Write([]byte(fmt.Sprintf("Role type %s does not exist", req.URL.Query().Get("type"))))
			return
		}

		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(http.StatusOK)
		json.NewEncoder(resp).Encode(rolesMap[req.URL.Query().Get("type")])
	}))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := &jenkinsrole.Client{
				HostName: testServer.URL,
				User:     tc.headerUser,
				Token:    tc.headerToken,
			}

			rwu, err := c.GetAllRoles(tc.roleType)

			if !tc.expectError {
				assert.NoError(t, err)
				assert.EqualValues(t, tc.rolesWithUsers, rwu)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
