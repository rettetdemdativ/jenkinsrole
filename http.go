// Author(s): Michael Koeppl

package jenkinsrole

import (
	"encoding/base64"
	"fmt"
	"net/http"
)

func attachAuthHeader(req *http.Request, username, token string) {
	encodedAuthString := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, token)))
	req.Header.Add("Authorization", "Basic "+encodedAuthString)
}
