// Author(s): Michael Koeppl

package jenkinsrole

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	jenkinsHost  string
	jenkinsUser  string
	jenkinsToken string
)

func TestMain(m *testing.M) {
	jHost := flag.String("jenkins_host", "", "The URL of the Jenkins instance")
	jUser := flag.String("jenkins_user", "", "The Jenkins user to be used for testing")
	jToken := flag.String("jenkins_token", "", "The token for the given Jenkins user")

	flag.Parse()

	if *jHost == "" || *jUser == "" || *jToken == "" {
		panic("Missing params")
	}

	jenkinsHost = (*jHost)
	jenkinsUser = (*jUser)
	jenkinsToken = (*jToken)

	code := m.Run()

	// Perform teardown

	os.Exit(code)
}

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
	testCases := []struct {
		name string

		roleType    string
		roleName    string
		permissions []Permission
		overwrite   bool
		pattern     string

		expectError bool
	}{
		{"valid_global_all_perm", "projectRoles", "testRole1", []Permission{All}, true, "", false},
		{"valid_global_all_perm_pattern", "projectRoles", "testRole1", []Permission{All}, true, "Pattern.*", false},
		{"valid_global_spec_perm_pattern", "projectRoles", "testRole1", []Permission{ItemReadPermission, ItemCreatePermission}, true, "Pattern.*", false},
		{"missing_type", "", "testRole2", []Permission{All}, true, "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := NewClient(jenkinsHost, jenkinsUser, jenkinsToken)

			var err error
			if tc.pattern == "" {
				err = c.AddRole(tc.roleType, tc.roleName, tc.permissions, tc.overwrite)
			} else {
				err = c.AddRole(tc.roleType, tc.roleName, tc.permissions, tc.overwrite, tc.pattern)
			}

			if !tc.expectError {
				assert.NoError(t, err)

				req, _ := http.NewRequest(
					http.MethodGet,
					fmt.Sprintf("%s/role-strategy/strategy/getRole?type=%s&roleName=%s",
						jenkinsHost,
						tc.roleType,
						tc.roleName,
					),
					nil,
				)
				encodedAuthString := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", jenkinsUser, jenkinsToken)))
				req.Header.Add("Authorization", "Basic "+encodedAuthString)

				hc := &http.Client{}

				res, err := hc.Do(req)
				assert.NoError(t, err)
				defer res.Body.Close()
				assert.Equal(t, res.StatusCode, http.StatusOK)
				respBody, err := ioutil.ReadAll(res.Body)
				assert.NoError(t, err)
				r := &Role{}
				err = json.Unmarshal(respBody, r)
				assert.NoError(t, err)

				resPermMap := make(map[string]bool)
				if !permListContainsAllPermission(tc.permissions) {
					for _, p := range tc.permissions {
						resPermMap[p.getPermissionString()] = true
					}
				} else {
					for _, p := range permissionStrings {
						resPermMap[p] = true
					}
				}
				assert.EqualValues(t, resPermMap, r.PermissionIDs)

				if tc.pattern != "" {
					assert.Equal(t, tc.pattern, r.Pattern)
				}
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
			c := Client{
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
			c := Client{
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
			c := Client{
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
			c := Client{
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

		r := &Role{
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
			c := &Client{
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
	rwu := RolesWithUsers{
		"admin":    []string{"sid1", "sid2", "sid3"},
		"testrole": []string{},
	}
	rolesMap := map[string]RolesWithUsers{
		"globalRoles":  rwu,
		"projectRoles": make(RolesWithUsers),
	}

	testCases := []struct {
		name string

		headerUser     string
		headerToken    string
		roleType       string
		rolesWithUsers RolesWithUsers

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
			c := &Client{
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
