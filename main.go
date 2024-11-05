package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/gin-gonic/gin"
)

const policyCedar = `// Admin có thể truy cập mọi endpoint
permit (
    principal,
    action == Action::"call",
    resource
)
when { principal has role && principal.role == "admin" };

// User chỉ được truy cập /order/*
permit (
    principal,
    action == Action::"call",
    resource in ApiEndpoint::"/order/*"
)
when { principal has role && principal.role == "user" };`

const entitiesJSON = `[
    {
        "uid": { "type": "User", "id": "alice" },
        "attrs": { "role": "admin" },
        "parents": []
    },
    {
        "uid": { "type": "User", "id": "bob" },
        "attrs": { "role": "user" },
        "parents": []
    },
    {
        "uid": { "type": "ApiEndpoint", "id": "/order/create" },
        "attrs": { 
            "path": "/order/create",
            "method": "POST"
        },
        "parents": [{ "type": "ApiEndpoint", "id": "/order/*" }]
    },
    {
        "uid": { "type": "ApiEndpoint", "id": "/order/list" },
        "attrs": { 
            "path": "/order/list",
            "method": "GET"
        },
        "parents": [{ "type": "ApiEndpoint", "id": "/order/*" }]
    },
    {
        "uid": { "type": "ApiEndpoint", "id": "/order/*" },
        "attrs": {
            "path": "/order/*",
            "method": "*"
        },
        "parents": []
    },
    {
        "uid": { "type": "ApiEndpoint", "id": "/users" },
        "attrs": {
            "path": "/users",
            "method": "GET"
        },
        "parents": []
    }
]`

func main() {
	// Parse policies
	var policies []cedar.Policy
	for _, policyStr := range []string{policyCedar} {
		var policy cedar.Policy
		if err := policy.UnmarshalCedar([]byte(policyStr)); err != nil {
			log.Fatal(err)
		}
		policies = append(policies, policy)
	}

	// Create policy set
	ps := cedar.NewPolicySet()
	for i, policy := range policies {
		ps.Store(cedar.PolicyID(fmt.Sprintf("policy%d", i)), &policy)
	}

	// Parse entities
	var entities types.Entities
	if err := json.Unmarshal([]byte(entitiesJSON), &entities); err != nil {
		log.Fatal(err)
	}

	// Test endpoints
	testEndpoints := []struct {
		path   string
		method string
		id     string
	}{
		{"/order/create", "POST", "/order/create"},
		{"/order/list", "GET", "/order/list"},
		{"/order/123", "GET", "/order/123"},
		{"/users", "GET", "/users"}, // Endpoint không thuộc /order/*
	}

	for _, endpoint := range testEndpoints {
		req := cedar.Request{
			Principal: types.EntityUID{Type: "User"},
			Action:    types.EntityUID{Type: "Action", ID: "call"},
			Resource:  types.EntityUID{Type: "ApiEndpoint", ID: types.String(endpoint.id)},
		}

		ok, _ := ps.IsAuthorized(entities, req)
		fmt.Printf("Endpoint %s (%s): %v\n", endpoint.path, endpoint.method, ok)
	}
}

// Helper function để check API access
func checkAPIAccess(ps *cedar.PolicySet, entities types.Entities, username string, path string, method string) bool {
	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: types.String(username)},
		Action:    types.EntityUID{Type: "Action", ID: "call"},
		Resource:  types.EntityUID{Type: "ApiEndpoint", ID: types.String(getEndpointID(path))},
	}

	ok, _ := ps.IsAuthorized(entities, req)
	return bool(ok)
}

func getEndpointID(path string) string {
	return path
}

func GinCedarAuthMiddleware(ps *cedar.PolicySet, entities types.Entities) gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.GetString("username") // hoặc lấy từ JWT token
		path := c.Request.URL.Path
		method := c.Request.Method

		if !checkAPIAccess(ps, entities, username, path, method) {
			c.AbortWithStatus(403)
			return
		}
		c.Next()
	}
}
