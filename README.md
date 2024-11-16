# BuzzDB Row-Level Security Implementation

## Overview
This project implements row-level security in BuzzDB, adding fine-grained access control to ensure users can only access data they're authorized to view. The implementation introduces user authentication, access level controls, and security logging.

## Features
- User authentication with multiple access levels
 - Admin (Level 100): Full access
 - Regular User (Level 50): Medium and low security access
 - Restricted User (Level 25): Low security access only
- Row-level access control in database operations
- Security violation logging
- Access level verification during query execution

## Core Components
```cpp
// User Authentication
class User {
   std::string username;
   int access_level;
   bool canAccess(int row_access_level);
};

// Secure Tuple Storage
class Tuple {
   std::vector<std::unique_ptr<Field>> fields;
   int access_level;
};

// Security Logging
class SecurityLogger {
   static void logAccessDenied(username, attempted_level, operation);
};
```
## Implementation Example
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
