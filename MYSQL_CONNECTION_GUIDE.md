# MySQL Connection Guide for RESH

## Connecting to Remote MySQL Database

### Quick Start

To connect to a remote MySQL database and execute queries using `resh`:

```bash
# Basic connection with quoted DSN (recommended for passwords with special characters)
resh db://mysql/stocks.connect dsn='mysql://username:password@host:port/database'

# Execute a query after connecting
resh db://mysql/stocks.query sql="SELECT * FROM your_table LIMIT 10"
```

### Step-by-Step Instructions

**Option 1: Traditional Two-Step Process**

1. **Connect to the Database**
   ```bash
   resh db://mysql/stocks.connect dsn='mysql://smiller:Gaphan8b$@192.168.1.115:3306/stocks'
   ```

2. **Execute a Query**
   ```bash
   resh db://mysql/stocks.query sql="SELECT * FROM stocks LIMIT 5"
   ```

3. **Execute Commands (INSERT, UPDATE, DELETE)**
   ```bash
   resh db://mysql/stocks.exec sql="INSERT INTO stocks (symbol, price) VALUES ('AAPL', 150.00)"
   ```

**Option 2: Auto-Connect (Recommended for CLI usage)**

1. **Query with Auto-Connect**
   ```bash
   resh db://mysql/stocks.query dsn='mysql://smiller:Gaphan8b$@192.168.1.115:3306/stocks' sql="SELECT * FROM stocks LIMIT 5"
   ```

2. **Exec with Auto-Connect**
   ```bash
   resh db://mysql/stocks.exec dsn='mysql://smiller:Gaphan8b$@192.168.1.115:3306/stocks' sql="INSERT INTO stocks (symbol, price) VALUES ('AAPL', 150.00)"
   ```

> **Note**: When using auto-connect, the DSN parameter can be provided directly to `query` and `exec` commands. If no existing connection is found for the alias, resh will automatically establish a connection using the provided DSN.

### DSN Format

The Data Source Name (DSN) follows this format:
```
mysql://username:password@host:port/database
```

**Components:**
- `username`: Your MySQL username
- `password`: Your MySQL password
- `host`: MySQL server hostname or IP address
- `port`: MySQL server port (typically 3306)
- `database`: Name of the database to connect to

### Handling Special Characters in Passwords

If your password contains special characters (like `$`, `@`, `#`, etc.), you have two options:

#### Option 1: Use Single Quotes (Recommended)
```bash
resh db://mysql/stocks.connect dsn='mysql://smiller:Gaphan8b$@192.168.1.115:3306/stocks'
```

#### Option 2: URL-Encode Special Characters
```bash
resh db://mysql/stocks.connect dsn=mysql://smiller:Gaphan8b%24@192.168.1.115:3306/stocks
```

**Common URL Encodings:**
- `$` → `%24`
- `@` → `%40`
- `#` → `%23`
- `%` → `%25`
- ` ` (space) → `%20`

### Common Error and Solutions

#### Shell Variable Expansion Error
**Error Message:**
```
Invalid DSN: missing @ symbol in connection string
Password may contain special characters that were interpreted by shell.
Use single quotes around DSN or URL-encode special characters ($ becomes %24)
```

**Cause:** The shell interpreted special characters in your password (particularly `$` symbols).

**Solutions:**
1. Wrap the DSN in single quotes: `dsn='mysql://...'`
2. URL-encode the special characters: `$` becomes `%24`

### Examples

#### Traditional Connection Method
```bash
# Connect first, then query
resh db://mysql/myapp.connect dsn='mysql://root:password@localhost:3306/myapp'
resh db://mysql/myapp.query sql="SELECT COUNT(*) FROM users"
```

#### Auto-Connect Method (Recommended)
```bash
# Query directly with DSN - connection established automatically
resh db://mysql/myapp.query dsn='mysql://root:password@localhost:3306/myapp' sql="SELECT COUNT(*) FROM users"
```

#### Remote Connection with Special Characters
```bash
# Password contains $ character - use quotes and auto-connect
resh db://mysql/production.query dsn='mysql://admin:P@ssw0rd$123@prod-server:3306/production_db' sql="SELECT version()"
```

#### Query Examples with Auto-Connect
```bash
# Select data
resh db://mysql/stocks.query dsn='mysql://user:pass@host:3306/stocks' sql="SELECT symbol, price FROM stocks WHERE price > 100"

# Count records
resh db://mysql/stocks.query dsn='mysql://user:pass@host:3306/stocks' sql="SELECT COUNT(*) as total_stocks FROM stocks"

# Insert data
resh db://mysql/stocks.exec dsn='mysql://user:pass@host:3306/stocks' sql="INSERT INTO stocks (symbol, price, volume) VALUES ('GOOGL', 2800.50, 1000000)"

# Update data
resh db://mysql/stocks.exec dsn='mysql://user:pass@host:3306/stocks' sql="UPDATE stocks SET price = 151.25 WHERE symbol = 'AAPL'"
```

### Connection Testing

**Traditional Method:**
```bash
# Test connection
resh db://mysql/test.connect dsn='mysql://user:pass@host:3306/db'

# Simple test query
resh db://mysql/test.query sql="SELECT 1 as test"
```

**Auto-Connect Method (Recommended):**
```bash
# Test connection and query in one step
resh db://mysql/test.query dsn='mysql://user:pass@host:3306/db' sql="SELECT 1 as test"
```

### Troubleshooting

1. **Connection Refused**: Check if MySQL server is running and accepting connections
2. **Access Denied**: Verify username, password, and user permissions
3. **Database Not Found**: Ensure the database name is correct
4. **Special Character Issues**: Use single quotes around the DSN or URL-encode characters

### Enhanced Error Detection

RESH now provides enhanced error detection for common issues:
- Detects shell variable expansion problems
- Suggests solutions for special character handling
- Provides clear error messages with actionable guidance
- **Auto-connect capability**: Query and exec commands can accept DSN parameter for automatic connection establishment