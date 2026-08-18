# Chronicle Inventory — functional local build

## Start

Double-click `start.bat`, or run:

`python server.py`

The app opens at `http://127.0.0.1:8765`. On first launch, create one local username and a password of at least 12 characters. The database is stored under `%LOCALAPPDATA%\ChronicleInventory\data` by default.

The server refuses non-loopback hosts. It is not accessible from other computers.

## Backup

Close the app and double-click `backup.bat`. It creates a consistent database backup and SHA-256 manifest under `%LOCALAPPDATA%\ChronicleInventory\data\backups`. Copy completed backups to an encrypted external drive for recovery from PC failure.

## Current working scope

- Local account creation, sign-in, sign-out, session timeout, and login throttling
- Local password change with all-session sign-out
- Persistent SQLite inventory
- Add and edit individual new/second-hand watches
- Allow multiple physical watches to share a model SKU while requiring a unique unit code for each watch
- Filter inventory by status and condition; search reference, serial, SKU, unit code, brand, or model
- Sort by update date, brand, cost, or price
- Archive inactive records without deleting their audit history
- Configure dashboard inventory-aging periods
- Validate unique brand/serial combinations, non-future acquisition dates, SKU/unit-code format, and USD amounts to two decimals
- Search inventory and calculate dashboard totals
- Maintain an active/inactive supplier directory with contact and website details
- Create purchase orders with supplier, dates, status, multiple item lines, quantity, unit cost, shipping, tax, and calculated total
- CSV import with add/update behavior and row-level errors
- CSV export without changing the original workbook
- Audit records for accounts, logins, watch changes, imports, and exports
- Consistent SQLite backup tool with integrity and checksum verification
- Strict local HTTP security headers and CSRF protection

Customers, sales/orders, returns, expenses, and reports now have clearly marked navigation placeholders. Their transaction workflows, plus photos, source verification, Excel `.xlsx`, backup UI, and marketplace publishing, remain later phases.
