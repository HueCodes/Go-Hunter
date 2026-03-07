package auth_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/auth"
)

// BenchmarkJWTTokenGeneration benchmarks JWT token generation
func BenchmarkJWTTokenGeneration(b *testing.B) {
	jwtService := auth.NewJWTService("benchmark-secret-key-for-testing", 24*time.Hour)
	userID := uuid.New()
	orgID := uuid.New()
	email := "benchmark@example.com"

	b.Run("OwnerRole", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = jwtService.GenerateToken(userID, orgID, email, "owner")
		}
	})

	b.Run("AdminRole", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = jwtService.GenerateToken(userID, orgID, email, "admin")
		}
	})

	b.Run("MemberRole", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = jwtService.GenerateToken(userID, orgID, email, "member")
		}
	})
}

// BenchmarkJWTTokenValidation benchmarks JWT token validation
func BenchmarkJWTTokenValidation(b *testing.B) {
	jwtService := auth.NewJWTService("benchmark-secret-key-for-testing", 24*time.Hour)
	userID := uuid.New()
	orgID := uuid.New()
	email := "benchmark@example.com"

	// Pre-generate tokens for validation benchmarks
	token, _ := jwtService.GenerateToken(userID, orgID, email, "owner")

	b.Run("ValidToken", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = jwtService.ValidateToken(token)
		}
	})

	b.Run("InvalidToken", func(b *testing.B) {
		invalidToken := token + "invalid"
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = jwtService.ValidateToken(invalidToken)
		}
	})

	b.Run("MalformedToken", func(b *testing.B) {
		malformedToken := "not-a-valid-jwt-token"
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = jwtService.ValidateToken(malformedToken)
		}
	})
}

// BenchmarkJWTTokenRoundTrip benchmarks generating and validating tokens together
func BenchmarkJWTTokenRoundTrip(b *testing.B) {
	jwtService := auth.NewJWTService("benchmark-secret-key-for-testing", 24*time.Hour)
	userID := uuid.New()
	orgID := uuid.New()
	email := "benchmark@example.com"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token, _ := jwtService.GenerateToken(userID, orgID, email, "admin")
		_, _ = jwtService.ValidateToken(token)
	}
}

// BenchmarkJWTServiceCreation benchmarks creating new JWT service instances
func BenchmarkJWTServiceCreation(b *testing.B) {
	b.Run("ShortSecret", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = auth.NewJWTService("short", 24*time.Hour)
		}
	})

	b.Run("LongSecret", func(b *testing.B) {
		longSecret := "this-is-a-much-longer-secret-key-for-benchmarking-purposes-256-bits"
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = auth.NewJWTService(longSecret, 24*time.Hour)
		}
	})
}

// BenchmarkPasswordHashing benchmarks bcrypt password hashing
func BenchmarkPasswordHashing(b *testing.B) {
	b.Run("ShortPassword", func(b *testing.B) {
		password := "short123"
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = auth.HashPassword(password)
		}
	})

	b.Run("MediumPassword", func(b *testing.B) {
		password := "medium-length-password-123"
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = auth.HashPassword(password)
		}
	})

	b.Run("LongPassword", func(b *testing.B) {
		password := "this-is-a-very-long-password-that-someone-might-use-for-security-purposes-128-chars"
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = auth.HashPassword(password)
		}
	})
}

// BenchmarkPasswordVerification benchmarks bcrypt password verification
func BenchmarkPasswordVerification(b *testing.B) {
	password := "benchmark-password-123"
	hash, _ := auth.HashPassword(password)

	b.Run("CorrectPassword", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = auth.CheckPassword(password, hash)
		}
	})

	b.Run("IncorrectPassword", func(b *testing.B) {
		wrongPassword := "wrong-password-456"
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = auth.CheckPassword(wrongPassword, hash)
		}
	})
}

// BenchmarkPasswordHashAndVerify benchmarks the full hash and verify cycle
func BenchmarkPasswordHashAndVerify(b *testing.B) {
	password := "benchmark-password-123"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash, _ := auth.HashPassword(password)
		_ = auth.CheckPassword(password, hash)
	}
}

// BenchmarkParallelTokenGeneration benchmarks token generation with parallelism
func BenchmarkParallelTokenGeneration(b *testing.B) {
	jwtService := auth.NewJWTService("benchmark-secret-key-for-testing", 24*time.Hour)
	email := "benchmark@example.com"

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		userID := uuid.New()
		orgID := uuid.New()
		for pb.Next() {
			_, _ = jwtService.GenerateToken(userID, orgID, email, "admin")
		}
	})
}

// BenchmarkParallelTokenValidation benchmarks token validation with parallelism
func BenchmarkParallelTokenValidation(b *testing.B) {
	jwtService := auth.NewJWTService("benchmark-secret-key-for-testing", 24*time.Hour)
	userID := uuid.New()
	orgID := uuid.New()
	token, _ := jwtService.GenerateToken(userID, orgID, "benchmark@example.com", "admin")

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = jwtService.ValidateToken(token)
		}
	})
}
