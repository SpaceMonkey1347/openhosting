# OpenHosting

![OpenHosting Logo](https://cdn.discordapp.com/attachments/1186020574238081035/1349066982502305973/openhosting-logo.png?ex=67d1c009&is=67d06e89&hm=1efbaa29d84b3c7f1184cd3883a4d77f86ccee35d57089085bd60b2779885a51&)

**OpenHosting** is a self-hosted, privacy-focused cloud storage solution that gives you complete control over your data. Built with Python and Flask, it provides a modern, secure platform for file storage and sharing without compromising your digital privacy.

## ðŸŒŸ Features

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

## ðŸ–¼ï¸ Preview
(All text on thoes image is purely exemple, the zero knoladge encryption is just an exemple)
### Main Page
![Main Page](https://cdn.discordapp.com/attachments/1186020574238081035/1349124172768612394/image.png?ex=67d1f54c&is=67d0a3cc&hm=ebe55b9791724c50cff739eea9a3de57cdb5000804883b17928c47d97a7a0608&)

### User Files Interface
![User Files Interface](https://cdn.discordapp.com/attachments/1186020574238081035/1349124334572011590/image.png?ex=67d1f572&is=67d0a3f2&hm=20a473f2584dccdf0a69f1c55d5a9854fbdbdbcf4c747e99afc7f3aed1746ec2&)

### Admin Panel Preview
![Admin Panel](https://media.discordapp.net/attachments/1186020574238081035/1349124709903503380/image.png?ex=67d1f5cc&is=67d0a44c&hm=6b5ca716870fb37038b81cdf445aacd7acc86b20d2694e08018a9ee6577d1c3d&=&format=webp&quality=lossless&width=3380&height=1151)

## ðŸ“‹ Requirements

- **Python 3.11** (required)
- Flask and its dependencies (see requirements.txt)
- Modern web browser
- SQLite (default) or other database supported by SQLAlchemy

## ðŸš€ Installation

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

## ðŸ‘¨â€ðŸ’» Default Admin Credentials

On first installation, the following default credentials are created:
- Username: `Admin`
- Password: `Admin`

**Important**: You will be required to change these credentials upon first login.

## ðŸ”§ Configuration

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

## ðŸ› ï¸ Development

### Project Structure

- `app.py`: Main application file
- `models.py`: Database models
- `templates/`: HTML templates
- `static/`: Static files (CSS, JS, images)
- `user_uploads/`: Directory for uploaded files
- `requirements.txt`: List of Python dependencies

### Database

OpenHosting uses SQLite by default. The database file is created automatically on first run.

## ðŸ“œ License

OpenHosting is open source software licensed under a custom license:

- **Personal and Non-Commercial Use**: Free for personal and non-commercial use.
- **Commercial Use**: Commercial use is prohibited unless commercial rights are purchased.
- **Modification**: You are free to modify the software for personal use.
- **Distribution**: You may distribute the software as long as you maintain the same license terms.

For commercial licensing inquiries, please contact the project maintainers.

## ðŸ¤ Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## ðŸ“ž Support

If you encounter any issues or have questions, please file an issue on the GitHub repository.

## ðŸ“‹ Changelog

### Patch Notes – October 9, 2025
- Hardened secret key lifecycle: auto-generated per-instance key with secure file permissions, administrative rotation workflow, and improved default admin onboarding.
- Enabled comprehensive CSRF protection using Flask-WTF and propagated hidden tokens across every form and Dropzone upload request.
- Restored strict session handling with idle timeouts, secure cookie defaults, and consistent logout/session cleanup helpers.
- Strengthened authentication flows by enforcing stronger credential validation during registration and first-run admin credential updates, including optional key regeneration.
- Secured file uploads end-to-end by constraining storage paths, validating content length, enforcing quotas in classic/chunked uploads, and standardizing JSON error responses.
- Added admin tooling to rotate the Flask secret key after backup restores and clarified UI messaging about the impact on active sessions.

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
- Hardened secret key lifecycle: auto-generated per-instance key with secure file permissions, administrative rotation workflow, and improved default admin onboarding.
- Enabled comprehensive CSRF protection using Flask-WTF and propagated hidden tokens across every form and Dropzone upload request.
- Restored strict session handling with idle timeouts, secure cookie defaults, and consistent logout/session cleanup helpers.
- Strengthened authentication flows by enforcing stronger credential validation during registration and first-run admin credential updates, including optional key regeneration.
- Secured file uploads end-to-end by constraining storage paths, validating content length, enforcing quotas in classic/chunked uploads, and standardizing JSON error responses.
- Added admin tooling to rotate the Flask secret key after backup restores and clarified UI messaging about the impact on active sessions.
---

## Credits

Special thanks to the following contributors:

- **somethingLethal**: For suggesting the idea about implementation of UUIDs as primary keys, improving security and preventing enumeration attacks.

---

Made with â¤ï¸ by the OpenHosting Team 

