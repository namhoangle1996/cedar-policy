package main

import (
	"encoding/json"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"log"
	"net/http"
	"sync"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
)

var JWT_SECRET_KEY = "your-secret-key"

// CedarConfig holds the current Cedar configuration
type CedarConfig struct {
	policySet *cedar.PolicySet
	entities  types.Entities
	mu        sync.RWMutex
}

// Config structure for Viper
type Config struct {
	Policy   string `mapstructure:"policy"`   // Policy content
	Entities string `mapstructure:"entities"` // Entities JSON content
}

// NewCedarConfig creates a new CedarConfig instance
func NewCedarConfig() *CedarConfig {
	return &CedarConfig{
		policySet: cedar.NewPolicySet(),
	}
}

// UpdateConfig updates Cedar configuration from Viper config
func (c *CedarConfig) UpdateConfig(cfg *Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update policy
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(cfg.Policy)); err != nil {
		return fmt.Errorf("failed to parse policy: %v", err)
	}

	// Create new policy set
	newPolicySet := cedar.NewPolicySet()
	newPolicySet.Store("policy0", &policy)

	// Update entities
	var entities types.Entities
	if err := json.Unmarshal([]byte(cfg.Entities), &entities); err != nil {
		return fmt.Errorf("failed to parse entities: %v", err)
	}

	// Apply updates
	c.policySet = newPolicySet
	c.entities = entities

	log.Println("Cedar configuration updated successfully")
	return nil
}

// GetConfig returns current policy set and entities
func (c *CedarConfig) GetConfig() (*cedar.PolicySet, types.Entities) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.policySet, c.entities
}

// InitViper initializes Viper configuration
func InitViper(cedarConfig *CedarConfig) error {
	viper.SetConfigName("config")  // config file name without extension
	viper.SetConfigType("yaml")    // or "json", "toml" etc
	viper.AddConfigPath("config/") // config file path

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read config: %v", err)
	}

	// Initial load of configuration
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return fmt.Errorf("failed to unmarshal config: %v", err)
	}

	// Apply initial configuration
	if err := cedarConfig.UpdateConfig(&cfg); err != nil {
		return fmt.Errorf("failed to apply initial config: %v", err)
	}

	// Watch for config changes
	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Printf("Config file changed: %s", e.Name)

		var newCfg Config
		if err := viper.Unmarshal(&newCfg); err != nil {
			log.Printf("Failed to unmarshal new config: %v", err)
			return
		}

		if err := cedarConfig.UpdateConfig(&newCfg); err != nil {
			log.Printf("Failed to apply new config: %v", err)
			return
		}
	})

	return nil
}

// GinCedarAuthMiddleware creates middleware using CedarConfig
func GinCedarAuthMiddleware(config *CedarConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		role := c.GetString("role")

		path := c.Request.URL.Path
		log.Println("get_path", path)

		ps, entities := config.GetConfig()

		req := cedar.Request{
			Principal: types.EntityUID{Type: "Role", ID: types.String(role)},
			Action:    types.EntityUID{Type: "Action", ID: "call"},
			Resource:  types.EntityUID{Type: "ApiEndpoint", ID: types.String(path)},
		}

		ok, _ := ps.IsAuthorized(entities, req)
		if !ok {
			c.AbortWithStatus(403)
			return
		}
		c.Next()
	}
}

func main() {
	// Initialize Cedar config
	cedarConfig := NewCedarConfig()

	// Initialize Viper
	if err := InitViper(cedarConfig); err != nil {
		log.Fatal(err)
	}

	// Initialize Gin
	r := gin.Default()

	// Use the middleware with config
	authorized := r.Group("/")
	//authorized.Use(JWTAuthMiddleware())
	authorized.Use(GinCedarAuthMiddleware(cedarConfig))

	// API endpoints
	authorized.POST("/order/create", createOrder)
	authorized.GET("/order/list", listOrders)
	authorized.GET("/users", listUsers)

	err := r.Run(":8888")
	if err != nil {
		return
	}
}

func listUsers(context *gin.Context) {

}

func listOrders(context *gin.Context) {

}

func createOrder(context *gin.Context) {

}

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

func JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No authorization header"})
			c.Abort()
			return
		}

		// Parse JWT token
		tokenString := authHeader[7:] // Remove "Bearer " prefix
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(JWT_SECRET_KEY), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Set username và role vào context
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Next()
	}
}
