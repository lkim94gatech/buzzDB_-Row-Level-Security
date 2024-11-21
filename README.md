# BuzzDB Row-Level Security Implementation

## Overview
This project enhances BuzzDB by implementing robust row-level security, providing fine-grained access control to ensure users can only access data they are authorized to view. The implementation includes user authentication, dynamic role-based access control, multi-table security, security-aware query execution, and advanced logging for auditing and debugging.

## Features
- **User Authentication and Role Management**
  - Admin (Level 100): Full access to all data
  - Regular User (Level 50): Access to medium and low-security data
  - Restricted User (Level 25): Access to low-security data only
  - Dynamic role assignment: Adjust permissions at runtime without recreating accounts
- **Row-Level Access Control**
  - Enforced in all database operations, including filtering, aggregation, and multi-table joins
- **Multi-Table Security**
  - Cross-table permission inheritance and security checks for multi-table queries
- **Advanced Security Features**
  - Security-aware query execution with predicate enforcement
  - Optimized query execution using caching for security predicates
  - Cost-based query optimization for efficient multi-table queries
- **Performance Enhancements**
  - Indexing for security filters
  - Predicate pushdown for reduced data processing overhead
  - Optimized hash joins for multi-table queries
- **Security Logging and Auditing**
  - Comprehensive logging of unauthorized access attempts and data modifications
  - Tracks security violations with detailed metadata for auditing
- **Error Handling**
  - Handling of invalid queries, unauthorized access, and duplicate table creation
  - Provides detailed feedback and ensures system reliability

## Core Components
```cpp
// User Authentication and Role-Based Access
class User {
   std::string username;
   int access_level;
   bool canAccess(int row_access_level);
};

// Tuple with Row-Level Security
class Tuple {
   std::vector<std::unique_ptr<Field>> fields;
   int access_level;
};

// Security Logging and Auditing
class SecurityLogger {
   static void logAccessDenied(std::string username, int attempted_level, std::string operation);
};

// Multi-Table Role Management
class RoleManager {
   std::unordered_map<std::string, Role> roles;
   bool hasPermission(std::string role, int access_level);
};
```
## Recent Updates

### From 75% to 100% Implementation:
- **Multi-Table Security:**
  - Added cross-table security checks and permission inheritance.
- **Dynamic Role Management:**
  - Enabled runtime permission updates for enhanced flexibility.
- **Advanced Query Processing:**
  - Implemented security-aware execution for complex queries.
  - Introduced hash join strategies for optimized multi-table queries.
- **Performance Optimizations:**
  - Added support for indexing security filters and predicate caching.
  - Integrated cost-based query optimization for efficient execution.
- **Error Handling:**
  - Enhanced system reliability with detailed error feedback.

### Implementation Example
```cpp
// Example output showing security in action:
=== Testing User1 (Level 50) ===
Access Denied - User: user1 attempted to access level 75
Expected error for User1: Insufficient privileges
User1: Inserted tuple with level 50  // Success
User1: Inserted tuple with level 25  // Success

=== Testing User2 (Level 25) ===
Access Denied - User: user2 attempted to access level 50
Expected error for User2: Insufficient privileges
User2: Inserted tuple with level 25  // Success
User2: Inserted tuple with level 0   // Success
```
