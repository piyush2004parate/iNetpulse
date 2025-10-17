# iNetPulse 🌐📊🛡️

**iNetpulse** is a comprehensive network traffic analysis tool designed to provide deep insights into network activity, ensuring performance optimization, security enhancement, and real-time monitoring.

Developed as part of the B.E. Computer Science and Engineering program at Xavier Institute of Engineering (Mumbai University), it integrates multiple modules to analyze, monitor, and secure network operations effectively.

## 🚀 Overview

iNetpulse offers a modular architecture that empowers network administrators and cybersecurity professionals to track, visualize, and secure their networks in real time.

It combines packet analysis, traffic monitoring, and anomaly detection with intuitive data visualization and alert systems, making it a robust solution for modern network management.

## 📸 Screenshots

Here are some glimpses of iNetpulse in action:

### Main Dashboard
![Main Dashboard](https://github.com/piyush2004parate/iNetpulse/blob/main/static/Images/HomePage.jpeg)

### Packet Analysis (Ethernet Frame)
![Packet Analysis Ethernet Frame](https://github.com/piyush2004parate/iNetpulse/blob/main/static/Images/PacketAnalysis.jpg)

### Speed & Performance Analysis
![Speed and Performance Analysis](https://github.com/piyush2004parate/iNetpulse/blob/main/static/Images/SpeedPerformance.jpg)

### Traffic Analysis (Connections & Bytes)
![Traffic Analysis Connections and Bytes](https://github.com/piyush2004parate/iNetpulse/blob/main/static/Images/TrafficGraph.jpg)

### Traffic Analysis (Detailed Graph)
![Traffic Analysis Detailed Graph](https://github.com/piyush2004parate/iNetpulse/blob/main/static/Images/TrafficAnalysis.jpg)

### Anomaly Detection (Scan in Progress)
![Anomaly Detection Scan in Progress](https://github.com/piyush2004parate/iNetpulse/blob/main/static/Images/AnomalyScanning.jpg)

### Anomaly Detection (JSON Output)
![Anomaly Detection JSON Output](https://github.com/piyush2004parate/iNetpulse/blob/main/static/Images/AnamolyDetection_Json.jpg)

### Anomaly Detection (Tabular Output)
![Anomaly Detection Tabular Output](https://github.com/piyush2004parate/iNetpulse/blob/main/static/Images/AnamolyDetection_Tabular.jpg)

### Protocol Detection
![Protocol Detection](https://github.com/piyush2004parate/iNetpulse/blob/main/static/Images/ProtocolDetection.jpg)

### Project Poster (Overall View)
![INetpulse Project Poster](https://github.com/piyush2004parate/iNetpulse/blob/main/static/Images/ProjectPoster.jpg)


## 🧩 Key Features

* **🔍 Packet Analysis:** Captures and inspects network packets to provide detailed insights into data flow, packet structure, and protocol behavior.
* **⚡ Speed & Performance Analysis:** Monitors bandwidth, latency, and throughput to identify performance bottlenecks and ensure optimal data transmission.
* **📊 Traffic Analysis:** Categorizes network traffic, tracks communication patterns, and visualizes data flow between hosts and protocols.
* **🛡️ Anomaly & Threat Detection:** Detects irregular activities and potential cyber threats (e.g., DDoS attacks, unauthorized access) using machine learning algorithms like Isolation Forest.
* **🌐 Protocol Detection:** Identifies and classifies network protocols such as TCP, UDP, ICMP, and HTTP for efficient and secure communication analysis.
* **🔔 Alert System:** Allows configuration of custom real-time alerts for performance degradation, abnormal traffic, or security breaches.

## 🧠 Tech Stack

| Category             | Technology Used                                 |
| :------------------- | :---------------------------------------------- |
| **Backend** | Python, Django                                  |
| **Frontend** | HTML, CSS, JavaScript                           |
| **Network Analysis** | Scapy, Wireshark (for understanding/verification) |
| **Data Visualization** | Matplotlib                                      |
| **Machine Learning** | Isolation Forest (for anomaly detection)        |
| **Performance Testing**| Speedtest library                               |
| **Data Handling** | CSV Files, DB SQL Lite                          |
| **Development Tools**| VS Code                                         |

## ⚙️ Installation & Setup

Follow the steps below to set up and run iNetpulse locally:

### Prerequisites

Before you begin, ensure you have the following installed:

* **Python 3.x**
* **pip** (Python package installer)
* **Git** (for cloning the repository)
* **Administrator/Root privileges** might be required for packet capture.

### 1️⃣ Clone the Repository

Open your terminal or command prompt and run:

```bash
git clone [https://github.com/piyush2004parate/INetpulse.git](https://github.com/piyush2004parate/INetpulse.git)
cd INetpulse
```
*(Replace `piyush2004parate` with your actual GitHub username if different, and `INetpulse` with your repository name if it differs.)*

### 2️⃣ Create a Virtual Environment

It's highly recommended to use a virtual environment to manage dependencies:

```bash
python -m venv venv
```

### 3️⃣ Activate the Virtual Environment

* **For Linux/macOS:**
    ```bash
    source venv/bin/activate
    ```
* **For Windows:**
    ```bash
    .\venv\Scripts\activate
    ```

### 4️⃣ Install Dependencies

With the virtual environment activated, install the required Python packages:

```bash
pip install -r requirements.txt
```

### 5️⃣ Apply Database Migrations (if applicable)

If your Django project uses a database, apply migrations to set it up:

```bash
python manage.py migrate
```

### 6️⃣ Run the Django Server

Start the local development server:

```bash
python manage.py runserver
```
*(Note: You might need to run this command with `sudo` on Linux/macOS or "Run as Administrator" on Windows if you encounter permissions errors related to network interfaces for packet capture.)*

### 7️⃣ Access the Web Interface

Open your web browser and navigate to:

👉 `http://127.0.0.1:8000/`

## 📂 Project Structure

A typical Django project structure for iNetpulse would look like this:

```
iNetpulse/
├── iNetpulse/                # Django project settings
│   ├── settings.py           # Core project settings
│   ├── urls.py               # Main URL configurations
│   └── wsgi.py               # WSGI entry-point for deployments
├── <your_app_name>/          # Main application for network analysis (e.g., 'analyzer', 'network_app')
│   ├── migrations/           # Database schema migrations
│   ├── templates/            # HTML templates for the web interface
│   ├── static/               # Frontend assets like CSS, JavaScript, images
│   ├── views.py              # Django views handling web requests and logic
│   ├── models.py             # Database models for data storage
│   ├── admin.py              # Django admin configurations
│   └── urls.py               # App-specific URL configurations
├── data/                     # Folder for CSV data storage (e.g., raw packet logs, analysis results)
├── venv/                     # Python virtual environment (created during setup)
├── manage.py                 # Django's command-line utility
├── requirements.txt          # List of Python dependencies
└── README.md                 # This README file
```

*(Note: `<your_app_name>` would be the actual name of your Django application within the project, e.g., `network_monitor` or `analysis_app`)*

## 🧪 Troubleshooting

* **Visualization Issues:** Ensure Matplotlib and its dependencies are properly installed. If charts don't render, check your browser's console for JavaScript errors.
* **Packet Capture Errors:** Running the Django server with `python manage.py runserver` might not have sufficient privileges to access network interfaces. Try running your terminal/IDE as administrator (Windows) or using `sudo python manage.py runserver` (Linux/macOS). Be cautious when using `sudo`.
* **Database Errors:** If you encounter issues with data persistence or integrity, try clearing or recreating CSV files in the `/data` folder, or running `python manage.py makemigrations` followed by `python manage.py migrate` if you made changes to models.
* **"Port already in use" error:** If you see an error like `Address already in use`, it means another process is using port `8000`. You can either kill that process or run Django on a different port: `python manage.py runserver 8001`.

## 🧭 Future Enhancements

* Integration of AI-driven predictive analytics for proactive threat prevention.
* Advanced alert customization for network anomalies (e.g., email, SMS notifications).
* Improved dashboards with more interactive and dynamic visualizations (e.g., using D3.js or other charting libraries).
* Integration with third-party security tools and SIEM (Security Information and Event Management) systems.
* Cloud-based monitoring support for distributed environments.

## 🏁 Conclusion

iNetpulse bridges the gap between network performance analysis and cyber threat detection, providing a single, intuitive platform for both. Its modular design, real-time analytics, and visualization capabilities make it a scalable solution for organizations of all sizes.

## 👨‍💻 Authors

* Piyush Parate (202204045)
* Pankaj Singh (202204055)
* Anurag Tiwari (202204059)

### 📘 Under the guidance of Prof. Lalita Moharkar

## 🏫 Institution

**Xavier Institute of Engineering**
Department of Computer Science and Engineering
University of Mumbai (2024–2025)

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file in the repository for details.
