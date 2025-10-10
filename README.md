### please use Python 3.11:)!


﻿# OpenHosting

![OpenHosting Logo](https://media.discordapp.net/attachments/1186020574238081035/1349066982502305973/openhosting-logo.png?ex=68e93e09&is=68e7ec89&hm=256e7db71bad07b5608d8d1e9913a152a71003bf63acdd4da8e52381cfd35b91&=&format=webp&quality=lossless&width=2400&height=750)

**OpenHosting** is a self-hosted, privacy-focused cloud storage solution that gives you complete control over your data. Built with Python and Flask, it provides a modern, secure platform for file storage and sharing without compromising your digital privacy.

## Features

### User Management
- **User Registration**: Allow users to create accounts with customizable storage limits
- **Admin Dashboard**: Manage users, storage quotas, and system settings
- **Role-Based Access**: Separate user and administrator privileges
- **First Login Security**: Force password change on first login for default admin account

### File Management
- **File Upload**: Simple drag-and-drop interface for uploading files
- **Chunk Upload**: Support for large file uploads with chunking
- **File Organization**: Browse, download, and manage your uploaded files
- **Storage Quotas**: Set and enforce storage limits for each user

### Backup System
- **Database Backups**: Create complete backups of your database with one click
- **User Files Backup**: Include user uploaded files in your backups
- **Backup Management**: View, download, delete, and restore backups from the admin interface
- **Backup Restoration**: Easily restore your system to a previous state using any backup
- **Manual Backup Control**: Backups are only created when an administrator explicitly requests it
- **Configurable Backup Path**: Set custom directory for storing backups
- **Automatic Backups**: Schedule automatic backups at regular intervals (coming soon)

### Security
- **Secure Authentication**: User authentication with password hashing
- **Privacy-Focused**: No tracking, no data mining, just simple file storage
- **Customizable Security**: Change default admin credentials for enhanced security

### Customization
- **Site Settings**: Customize site title, description, and features
- **Icon Customization**: Change feature icons using custom SVG code
- **Appearance Settings**: Modify the look and feel of your OpenHosting instance
- **Footer Customization**: Personalize footer text and information

### User Interface
- **Modern Design**: Clean, responsive interface built with Tailwind CSS
- **Dark Mode**: Easy on the eyes with a dark-themed interface
- **Mobile-Friendly**: Access your files from any device with a responsive design

## Preview
(All text on thoes image is purely exemple, the zero knoladge encryption is just an exemple)
### Main Page
![Main Page](https://media.discordapp.net/attachments/1186020574238081035/1349124172768612394/image.png?ex=68e9734c&is=68e821cc&hm=d0befbdad049f8bd7dc2152667545682269a0908eb351555fa504c20454b6f09&=&format=webp&quality=lossless&width=2215&height=896)


### User Files Interface
![User Files Interface](https://media.discordapp.net/attachments/1186020574238081035/1349124334572011590/image.png?ex=68e97372&is=68e821f2&hm=78d3fa1e654b712de4f97b010711a6e550e70649a542fd62fdabd1bb2adff082&=&format=webp&quality=lossless&width=2326&height=1290)

### Admin Panel Preview
![Admin Panel](https://media.discordapp.net/attachments/1186020574238081035/1349124709903503380/image.png?ex=68e973cc&is=68e8224c&hm=8ed9679873b0c40c5af9d75acb5c03c86e76a4ca6e1f9fa0416cf876b98c44b7&=&format=webp&quality=lossless&width=3380&height=1151)

## Requirements

- **Python 3.11** (required)
- Flask and its dependencies (see requirements.txt)
- Modern web browser
- SQLite (default) or other database supported by SQLAlchemy

## Installation

### Windows

1. Clone the repository:
   ```
   git clone https://github.com/Ciela2002/openhosting.git
   cd openhosting
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the start script:
   ```
   start_server.bat
   ```

4. Access OpenHosting at http://127.0.0.1:83

### Linux/macOS

1. Clone the repository:
   ```
   git clone https://github.com/Ciela2002/openhosting.git
   cd openhosting
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Make the start script executable and run it:
   ```
   chmod +x start_server.sh
   ./start_server.sh
   ```

4. Access OpenHosting at http://127.0.0.1:83

## Default Admin Credentials

On first installation, the following default credentials are created:
- Username: `Admin`
- Password: `Admin`

**Important**: You will be required to change these credentials upon first login.

## Configuration

### Storage Limits

Default storage limits can be configured in the admin dashboard. The default is 5GB per user.

### Backup Configuration

1. Log in as an administrator
2. Navigate to Admin > Backups
3. Configure backup settings:
   - Set backup directory path
   - Choose whether to include user files in backups
   - Enable/disable automatic backups (feature coming soon)
   - Set backup interval (feature coming soon)

### Customizing the Interface

1. Log in as an administrator
2. Navigate to Admin > Settings
3. Customize site title, descriptions, feature texts, and icons
4. Save your changes

## Development

### Project Structure

- `app.py`: Main application file
- `models.py`: Database models
- `templates/`: HTML templates
- `static/`: Static files (CSS, JS, images)
- `user_uploads/`: Directory for uploaded files
- `requirements.txt`: List of Python dependencies

### Database

OpenHosting uses SQLite by default. The database file is created automatically on first run.

## License

OpenHosting is open source software licensed under a custom license:

- **Personal and Non-Commercial Use**: Free for personal and non-commercial use.
- **Commercial Use**: Commercial use is prohibited unless commercial rights are purchased.
- **Modification**: You are free to modify the software for personal use.
- **Distribution**: You may distribute the software as long as you maintain the same license terms.

For commercial licensing inquiries, please contact the project maintainers.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Support

If you encounter any issues or have questions, please file an issue on the GitHub repository.

## Changelog


### Version 1.1.1
- Implemented UUIDs as primary keys for all database models
- Enhanced security by preventing enumeration attacks
- Fixed various bugs and improved stability

### Version 1.1.0
- **New Features**:
  - Added "Delete All" button to user dashboard for bulk file deletion
  - Added manual backup creation with clear user interface
  - Added backup management system with download, restore, and delete capabilities
  - Added icon customization in admin settings
  - Added first login security for default admin account
  - Added storage usage visualization
  - Added backup history with detailed information

- **Improvements**:
  - Enhanced navigation in admin panel with consistent hover effects
  - Improved backup page with clear instructions and manual creation button
  - Added version display in admin panel (1.1.1)
  - Improved mobile responsiveness throughout the application
  - Enhanced security with session management improvements
  - Optimized file upload process with chunking support

- **Bug Fixes**:
  - Fixed login redirect loop issue
  - Fixed backup creation behavior to only create backups when explicitly requested
  - Fixed user deletion form URL
  - Fixed session handling to prevent premature session expiration
  - Fixed admin navigation highlighting for backup-related pages
  - Fixed various UI inconsistencies in dark mode
  
### Patch Notes – October 9, 2025

**Security & Authentication Enhancements**:
- Hardened secret key lifecycle: auto-generated per-instance key with secure file permissions, administrative rotation workflow, and improved default admin onboarding.
- Enabled comprehensive CSRF protection using Flask-WTF and propagated hidden tokens across every form and Dropzone upload request.
- Restored strict session handling with idle timeouts, secure cookie defaults, and consistent logout/session cleanup helpers.
- Strengthened authentication flows by enforcing stronger credential validation during registration and first-run admin credential updates, including optional key regeneration.
- Secured file uploads end-to-end by constraining storage paths, validating content length, enforcing quotas in classic/chunked uploads, and standardizing JSON error responses.
- Added admin tooling to rotate the Flask secret key after backup restores and clarified UI messaging about the impact on active sessions.

**File Sharing Feature**:
- Added file sharing functionality with secure, shareable links using cryptographically secure tokens (32+ characters)
- Implemented password protection for shared links with password hashing
- Added expiration options (1 hour, 24 hours, 7 days, 30 days, or never)
- Added download limits to control how many times a file can be downloaded
- Created "My Shares" page for users to manage their active shares
- Added share analytics with detailed access logs tracking downloads, views, and last access times
- Implemented admin share management interface to view and manage all shares across the platform
- Added rate limiting for password attempts (5 attempts per 15 minutes) to prevent brute force attacks
- Added visual indicators for shared files in dashboard
- Implemented automatic share revocation when files are deleted
- Added share button to file cards with intuitive modal interfaces
- Created share creation modal with configuration options
- Added share success modal with copy link functionality
- Implemented mobile-responsive share interfaces
- Added "Shared Links" section to admin panel navigation
- Added access logging for security monitoring and analytics

## Credits

Special thanks to the following contributors:

- **somethingLethal**: For suggesting the idea about implementation of UUIDs as primary keys, improving security and preventing enumeration attacks.

---

Made by the OpenHosting Team 





