# OpenHosting

![OpenHosting Logo](https://via.placeholder.com/150x150.png?text=OpenHosting)

**OpenHosting** is a self-hosted, privacy-focused cloud storage solution that gives you complete control over your data. Built with Python and Flask, it provides a modern, secure platform for file storage and sharing without compromising your digital privacy.

## 🌟 Features

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

## 📋 Requirements

- **Python 3.11** (required)
- Flask and its dependencies (see requirements.txt)
- Modern web browser
- SQLite (default) or other database supported by SQLAlchemy

## 🚀 Installation

### Windows

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/openhosting.git
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
   git clone https://github.com/yourusername/openhosting.git
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

## 👨‍💻 Default Admin Credentials

On first installation, the following default credentials are created:
- Username: `Admin`
- Password: `Admin`

**Important**: You will be required to change these credentials upon first login.

## 🔧 Configuration

### Storage Limits

Default storage limits can be configured in the admin dashboard. The default is 5GB per user.

### Customizing the Interface

1. Log in as an administrator
2. Navigate to Admin > Settings
3. Customize site title, descriptions, feature texts, and icons
4. Save your changes

## 🛠️ Development

### Project Structure

- `app.py`: Main application file
- `models.py`: Database models
- `templates/`: HTML templates
- `static/`: Static files (CSS, JS, images)
- `user_uploads/`: Directory for uploaded files
- `requirements.txt`: List of Python dependencies

### Database

OpenHosting uses SQLite by default. The database file is created automatically on first run.

## 📜 License

OpenHosting is open source software licensed under a custom license:

- **Personal and Non-Commercial Use**: Free for personal and non-commercial use.
- **Commercial Use**: Commercial use is prohibited unless commercial rights are purchased.
- **Modification**: You are free to modify the software for personal use.
- **Distribution**: You may distribute the software as long as you maintain the same license terms.

For commercial licensing inquiries, please contact the project maintainers.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

If you encounter any issues or have questions, please file an issue on the GitHub repository.

---

Made with ❤️ by the OpenHosting Team 