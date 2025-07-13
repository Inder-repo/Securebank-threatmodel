import streamlit as st
import json
import base64
import logging
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image # Corrected Image import
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from PIL import Image as PILImage
import io
# import sqlite3 # Removed: Migrating to Firestore
import plotly.express as px
import csv
import streamlit.components.v1 as components
import os

# Configure logging
logging.basicConfig(filename="threat_modeling_app.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Initialize session state variables if they don't exist
if "role" not in st.session_state:
    st.session_state.role = "admin"
if "dfd_elements" not in st.session_state:
    st.session_state.dfd_elements = []
if "dfd_image" not in st.session_state:
    st.session_state.dfd_image = None
if "theme" not in st.session_state:
    st.session_state.theme = "light"
if "last_update" not in st.session_state:
    st.session_state.last_update = 0
if "tutorial_step" not in st.session_state:
    st.session_state.tutorial_step = 0
if "quiz_answers" not in st.session_state:
    st.session_state.quiz_answers = {}
if 'firebase_initialized' not in st.session_state:
    st.session_state.firebase_initialized = False
if 'db' not in st.session_state:
    st.session_state.db = None # Placeholder for Firestore DB instance
if 'auth' not in st.session_state:
    st.session_state.auth = None # Placeholder for Firebase Auth instance
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
if 'app_id' not in st.session_state:
    st.session_state.app_id = None
if 'firebase_config_json' not in st.session_state:
    st.session_state.firebase_config_json = "{}"
if 'initial_auth_token' not in st.session_state:
    st.session_state.initial_auth_token = None
if 'js_save_request' not in st.session_state:
    st.session_state.js_save_request = None
if 'js_load_request' not in st.session_state:
    st.session_state.js_load_request = False
if 'js_delete_request' not in st.session_state:
    st.session_state.js_delete_request = None
if 'threat_model' not in st.session_state:
    st.session_state.threat_model = {} # Initialize with empty threat model
if 'architecture' not in st.session_state:
    st.session_state.architecture = {'components': [], 'connections': []} # Initialize with empty architecture

# Apply Cloudscape-inspired CSS
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Noto+Sans:wght@400;500;700&display=swap');
    .stApp {
        font-family: 'Noto Sans', sans-serif;
        background-color: #f8f9fa;
        color: #0f1a44;
    }
    .stButton > button {
        background-color: #0073bb;
        color: white;
        border-radius: 4px;
        padding: 8px 16px;
        font-weight: 500;
        border: none;
        transition: background-color 0.2s ease-in-out;
        margin: 4px;
    }
    .stButton > button:hover {
        background-color: #005ea2;
    }
    .stButton > button.secondary {
        background-color: #ffffff;
        color: #0f1a44;
        border: 1px solid #0073bb;
    }
    .stButton > button.secondary:hover {
        background-color: #e9ecef;
    }
    .stTextInput > div > input, .stSelectbox > div > select, .stTextArea > div > textarea {
        border: 1px solid #d5dbdb;
        border-radius: 4px;
        padding: 8px;
        background-color: white;
        color: #0f1a44;
        transition: border-color 0.2s;
    }
    .stTextInput > div > input:focus, .stSelectbox > div > select:focus, .stTextArea > div > textarea:focus {
        border-color: #0073bb;
        box-shadow: 0 0 0 2px rgba(0, 115, 187, 0.3);
    }
    .stSidebar {
        background-color: #ffffff;
        border-right: 1px solid #d5dbdb;
        padding: 16px;
    }
    .stSidebar h2 {
        color: #0f1a44;
        font-size: 18px;
        font-weight: 700;
        margin-bottom: 16px;
    }
    .stExpander {
        border: 1px solid #d5dbdb;
        border-radius: 4px;
        background-color: #ffffff;
        margin-bottom: 8px;
    }
    .stExpander > div > div {
        padding: 8px 16px;
    }
    h1, h2, h3 {
        color: #0f1a44;
        font-weight: 700;
        margin-top: 16px;
    }
    .aws-divider {
        border-top: 1px solid #d5dbdb;
        margin: 16px 0;
    }
    .stTable {
        border-collapse: collapse;
        width: 100%;
        background-color: #ffffff;
        border: 1px solid #d5dbdb;
        border-radius: 4px;
    }
    .stTable th, .stTable td {
        border: 1px solid #d5dbdb;
        padding: 8px;
        text-align: left;
    }
    .stTable th {
        background-color: #e9ecef;
        font-weight: 500;
        color: #0f1a44;
    }
    .aws-button {
        display: inline-block;
        padding: 8px 16px;
        background-color: #0073bb;
        color: white;
        border-radius: 4px;
        text-decoration: none;
        font-weight: 500;
        margin-right: 8px;
    }
    .aws-button:hover {
        background-color: #005ea2;
    }
    </style>
""", unsafe_allow_html=True)

# Firebase Initialization (Python side - to get config and pass to JS)
if not st.session_state.firebase_initialized:
    st.session_state.app_id = globals().get('__app_id', 'default-app-id')
    firebase_config_from_globals_raw = globals().get('__firebase_config', '{}')
    try:
        firebase_config_dict = json.loads(firebase_config_from_globals_raw)
    except json.JSONDecodeError:
        st.error("Error parsing __firebase_config. Using empty config.")
        firebase_config_dict = {}

    st.session_state.firebase_config_json = json.dumps(firebase_config_dict)
    st.session_state.initial_auth_token = globals().get('__initial_auth_token', None)

    if firebase_config_dict:
        st.session_state.firebase_initialized = True
    else:
        st.warning("Firebase configuration not found. Persistence features will be unavailable.")

# Cache static data
@st.cache_data
def load_static_data():
    stride_library = {
        "Spoofing": [
            {"threat": "Unauthorized impersonation", "vulnerability": "Weak authentication", "risk": "High", "mitigation": "Implement MFA, strong passwords", "compliance": "NIST 800-63B", "example": "An attacker uses stolen credentials to access a banking portal."}
        ],
        "Tampering": [
            {"threat": "Data modification", "vulnerability": "Lack of integrity checks", "risk": "High", "mitigation": "Use TLS, checksums", "compliance": "NIST 800-53 SC-8", "example": "An attacker alters transaction data in an unencrypted API call."}
        ],
        "Information Disclosure": [
            {"threat": "Data exposure", "vulnerability": "Unencrypted channels", "risk": "High", "mitigation": "Use TLS 1.3, encrypt data at rest", "compliance": "GDPR Article 32", "example": "SQL injection exposes user data from a database."}
        ],
        "Denial of Service": [
            {"threat": "DDoS attack", "vulnerability": "No rate limiting", "risk": "High", "mitigation": "Implement Cloudflare, rate limiting", "compliance": "ISO 27001 A.12.1.3", "example": "A botnet floods an e-commerce site, causing downtime."}
        ],
        "Elevation of Privilege": [
            {"threat": "Privilege escalation", "vulnerability": "Insecure RBAC", "risk": "Critical", "mitigation": "Apply least privilege, audit roles", "compliance": "NIST 800-53 AC-6", "example": "An attacker exploits a misconfigured role to gain admin access."}
        ]
    }
    pre_defined_threat_models = [
        {
            "name": "Online Banking",
            "architecture": "Web app with React, Node.js, MySQL on AWS",
            "dfd_elements": [
                {"type": "External Entity", "name": "Customer", "technology": "Browser", "x": 50, "y": 50},
                {"type": "Process", "name": "Web Server", "technology": "React/Node.js", "x": 200, "y": 150},
                {"type": "Data Store", "name": "MySQL DB", "technology": "MySQL", "x": 350, "y": 150},
                {"type": "Data Flow", "name": "HTTP/S Request", "data_flow": "HTTP/S", "source": "Customer", "target": "Web Server"},
                {"type": "Data Flow", "name": "DB Query", "data_flow": "SQL", "source": "Web Server", "target": "MySQL DB"}
            ],
            "threats": [
                stride_library["Spoofing"][0],
                stride_library["Tampering"][0],
                stride_library["Information Disclosure"][0],
                stride_library["Denial of Service"][0],
                stride_library["Elevation of Privilege"][0]
            ]
        },
        {
            "name": "IoT Smart Home",
            "architecture": "IoT devices with MQTT, cloud backend on Azure",
            "dfd_elements": [
                {"type": "External Entity", "name": "User", "technology": "Mobile App", "x": 50, "y": 50},
                {"type": "Process", "name": "IoT Gateway", "technology": "MQTT Broker", "x": 200, "y": 150},
                {"type": "Data Store", "name": "Cloud Storage", "technology": "Azure Blob", "x": 350, "y": 150},
                {"type": "Data Flow", "name": "Sensor Data", "data_flow": "MQTT publish", "source": "User", "target": "IoT Gateway"},
                {"type": "Data Flow", "name": "Store Data", "data_flow": "HTTPS", "source": "IoT Gateway", "target": "Cloud Storage"}
            ],
            "threats": [
                stride_library["Spoofing"][0],
                stride_library["Information Disclosure"][0],
                stride_library["Denial of Service"][0]
            ]
        },
        {
            "name": "Mobile Banking App",
            "architecture": "Mobile app with REST API, PostgreSQL on GCP",
            "dfd_elements": [
                {"type": "External Entity", "name": "User", "technology": "Mobile Device", "x": 50, "y": 50},
                {"type": "Process", "name": "API Server", "technology": "REST API", "x": 200, "y": 150},
                {"type": "Data Store", "name": "PostgreSQL DB", "technology": "PostgreSQL", "x": 350, "y": 150},
                {"type": "Data Flow", "name": "API Request", "data_flow": "HTTPS", "source": "User", "target": "API Server"},
                {"type": "Data Flow", "name": "DB Access", "data_flow": "SQL", "source": "API Server", "target": "PostgreSQL DB"}
            ],
            "threats": [
                stride_library["Tampering"][0],
                stride_library["Information Disclosure"][0],
                stride_library["Elevation of Privilege"][0]
            ]
        }
    ]
    dfd_templates = {
        "Web Application": [
            {"id": "user_web", "type": "External Entity", "name": "User", "technology": "Browser", "x": 50, "y": 50},
            {"id": "web_server", "type": "Process", "name": "Web Server", "technology": "Node.js", "x": 200, "y": 150},
            {"id": "db_web", "type": "Data Store", "name": "Database", "technology": "MySQL", "x": 350, "y": 150},
            {"id": "flow_user_web", "type": "Data Flow", "name": "User Request", "data_flow": "HTTP request", "source": "user_web", "target": "web_server"},
            {"id": "flow_web_db", "type": "Data Flow", "name": "DB Query", "data_flow": "SQL", "source": "web_server", "target": "db_web"}
        ],
        "IoT System": [
            {"id": "user_iot", "type": "External Entity", "name": "User", "technology": "Mobile App", "x": 50, "y": 50},
            {"id": "iot_gateway", "type": "Process", "name": "IoT Gateway", "technology": "MQTT Broker", "x": 200, "y": 150},
            {"id": "cloud_storage", "type": "Data Store", "name": "Cloud Storage", "technology": "Azure Blob", "x": 350, "y": 150},
            {"id": "flow_user_iot", "type": "Data Flow", "name": "Sensor Data", "data_flow": "MQTT publish", "source": "user_iot", "target": "iot_gateway"},
            {"id": "flow_iot_cloud", "type": "Data Flow", "name": "Store Data", "data_flow": "HTTPS", "source": "iot_gateway", "target": "cloud_storage"}
        ],
        "Mobile App": [
            {"id": "user_mobile", "type": "External Entity", "name": "User", "technology": "Mobile Device", "x": 50, "y": 50},
            {"id": "api_server", "type": "Process", "name": "API Server", "technology": "REST API", "x": 200, "y": 150},
            {"id": "db_mobile", "type": "Data Store", "name": "Database", "technology": "PostgreSQL", "x": 350, "y": 150},
            {"id": "flow_user_api", "type": "Data Flow", "name": "API Request", "data_flow": "HTTPS", "source": "user_mobile", "target": "api_server"},
            {"id": "flow_api_db", "type": "Data Flow", "name": "DB Access", "data_flow": "SQL", "source": "api_server", "target": "db_mobile"}
            ]
    }
    return stride_library, pre_defined_threat_models, dfd_templates

# Report generation functions
@st.cache_data
def create_json_report(threat_model_name, architecture, dfd_elements, threats, _timestamp):
    report = {
        "threat_model_name": threat_model_name,
        "architecture": architecture,
        "dfd_elements": dfd_elements,
        "threats": threats,
        "generated_on": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "generated_by": st.session_state.user_id if st.session_state.user_id else "Anonymous"
    }
    report_json = json.dumps(report, indent=2)
    b64 = base64.b64encode(report_json.encode()).decode()
    return f'<a href="data:application/json;base64,{b64}" download="{threat_model_name}_report.json" class="aws-button">Download JSON Report</a>'

@st.cache_data
def create_csv_report(threat_model_name, threats, _timestamp):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Threat", "Vulnerability", "Risk", "Mitigation", "Compliance", "Example"])
    for threat in threats:
        writer.writerow([threat["threat"], threat["vulnerability"], threat["risk"], threat["mitigation"], threat["compliance"], threat["example"]])
    csv_data = output.getvalue().encode()
    b64 = base64.b64encode(csv_data).decode()
    return f'<a href="data:application/csv;base64,{b64}" download="{threat_model_name}_report.csv" class="aws-button">Download CSV Report</a>'

@st.cache_data
def create_pdf_report(threat_model_name, architecture, dfd_elements, threats, dfd_image, _timestamp):
    filename = f"temp_{threat_model_name}_report.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = [
        Paragraph(f"Threat Model: {threat_model_name}", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Architecture: {architecture}", styles["Normal"]),
        Spacer(1, 12),
    ]
    if dfd_image:
        try:
            img = PILImage.open(io.BytesIO(dfd_image))
            # Resize image to fit PDF page width, maintaining aspect ratio
            aspect_ratio = img.width / img.height
            pdf_img_width = 400 # Max width for image in PDF
            pdf_img_height = pdf_img_width / aspect_ratio
            
            # Ensure image doesn't exceed page height either
            if pdf_img_height > 200: # Max height for image in PDF
                pdf_img_height = 200
                pdf_img_width = pdf_img_height * aspect_ratio

            story.append(Paragraph("DFD Diagram", styles["Heading2"]))
            story.append(Image(io.BytesIO(dfd_image), width=pdf_img_width, height=pdf_img_height))
            story.append(Spacer(1, 12))
        except Exception as e:
            logger.error(f"Error embedding DFD image in PDF: {str(e)}")
            st.warning("Could not embed DFD image in PDF report.")

    story.extend([
        Paragraph("Threats", styles["Heading2"]),
        Table([["Threat", "Vulnerability", "Risk", "Mitigation", "Compliance", "Example"]] + [
            [threat["threat"], threat["vulnerability"], threat["risk"], threat["mitigation"], threat["compliance"], threat["example"]]
            for threat in threats
        ], style=[
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10), # Reduced font size for better fit
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ("LEFTPADDING", (0,0), (-1,-1), 2), # Add padding
            ("RIGHTPADDING", (0,0), (-1,-1), 2),
            ("TOPPADDING", (0,0), (-1,-1), 2),
            ("BOTTOMPADDING", (0,0), (-1,-1), 2),
        ], colWidths=[80, 80, 40, 120, 80, 120]) # Adjusted column widths
    ])
    doc.build(story)
    with open(filename, "rb") as f:
        pdf_data = f.read()
    b64 = base64.b64encode(pdf_data).decode()
    os.remove(filename)
    return f'<a href="data:application/pdf;base64,{b64}" download="{threat_model_name}_report.pdf" class="aws-button">Download PDF Report</a>'

@st.cache_data
def create_risk_chart(threats, _timestamp):
    risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for threat in threats:
        risk_counts[threat["risk"]] += 1
    df = pd.DataFrame(list(risk_counts.items()), columns=["Risk Level", "Count"])
    # Ensure all risk levels are present for consistent coloring
    all_levels = pd.DataFrame({"Risk Level": ["Low", "Medium", "High", "Critical"], "Count": 0})
    df = pd.concat([all_levels, df]).groupby("Risk Level", as_index=False).sum()
    
    # Define custom colors for risk levels
    color_map = {"Low": "#28a745", "Medium": "#ffc107", "High": "#fd7e14", "Critical": "#dc3545"}
    
    # Order risk levels for consistent chart display
    category_orders = {"Risk Level": ["Low", "Medium", "High", "Critical"]}

    fig = px.bar(df, x="Risk Level", y="Count", title="Risk Distribution", 
                 color="Risk Level", color_discrete_map=color_map,
                 category_orders=category_orders)
    fig.update_layout(
        plot_bgcolor="#ffffff",
        paper_bgcolor="#ffffff",
        font_color="#0f1a44",
        title_font_color="#0f1a44",
        title_font_size=16,
        margin=dict(l=40, r=40, t=40, b=40),
        xaxis_title="Risk Level",
        yaxis_title="Number of Threats"
    )
    return fig

# Validation and threat generation
def validate_input(value, field_name, max_length=255):
    if not value or len(value.strip()) == 0:
        return False, f"{field_name} cannot be empty."
    if len(value) > max_length:
        return False, f"{field_name} exceeds {max_length} characters."
    return True, ""

def validate_dfd(dfd_elements):
    processes = [e for e in dfd_elements if e["type"] == "Process"]
    if not processes:
        return False, "At least one Process is required in the DFD."
    return True, ""

def generate_threat_model_logic(dfd_elements, architecture_description, stride_library):
    """
    Generates a list of suggested threats based on DFD elements and architecture description.
    This is a rule-based system. For a more advanced commercial app, consider LLM integration.
    """
    threats = []
    
    # Basic rules based on DFD element types
    if any(e["type"] == "Process" for e in dfd_elements):
        threats.extend([stride_library["Spoofing"][0], stride_library["Elevation of Privilege"][0]])
    if any(e["type"] == "Data Store" for e in dfd_elements):
        threats.append(stride_library["Information Disclosure"][0])
    if any(e["type"] == "Data Flow" for e in dfd_elements):
        threats.append(stride_library["Tampering"][0])

    # Keyword-based rules from architecture description and element technologies
    keywords = {
        "web": ["Spoofing", "Tampering", "Denial of Service", "Information Disclosure"],
        "database": ["Information Disclosure", "Tampering", "Denial of Service"],
        "api": ["Denial of Service", "Spoofing", "Information Disclosure"],
        "iot": ["Spoofing", "Information Disclosure", "Tampering"],
        "mobile": ["Tampering", "Elevation of Privilege", "Spoofing"],
        "cloud": ["Denial of Service", "Information Disclosure", "Elevation of Privilege"],
        "payment": ["Tampering", "Repudiation", "Information Disclosure", "Spoofing"],
        "authentication": ["Spoofing", "Elevation of Privilege", "Denial of Service"]
    }
    
    architecture_lower = architecture_description.lower()
    for keyword, threat_types in keywords.items():
        if keyword in architecture_lower or any(keyword in e.get("technology", "").lower() for e in dfd_elements):
            for threat_type in threat_types:
                # Add unique threats from the library
                for threat_detail in stride_library[threat_type]:
                    if threat_detail not in threats: # Avoid duplicates
                        threats.append(threat_detail)
    
    # Ensure uniqueness by threat name
    seen_threat_names = set()
    unique_threats = []
    for t in threats:
        if t["threat"] not in seen_threat_names:
            unique_threats.append(t)
            seen_threat_names.add(t["threat"])
    
    return unique_threats

# Load static data
stride_library, pre_defined_threat_models, dfd_templates = load_static_data()

# Streamlit app configuration
st.set_page_config(page_title="Commercial Threat Modeling", layout="wide")
st.markdown('<h1 style="color: #0f1a44;">Commercial Threat Modeling Platform</h1>', unsafe_allow_html=True)
st.markdown("Design, analyze, and mitigate security threats with an interactive DFD editor, AI-powered insights, and comprehensive reporting.")
st.markdown('<div class="aws-divider"></div>', unsafe_allow_html=True)

# Theme toggle
theme = st.sidebar.selectbox("Theme", ["Light", "Dark"], index=0 if st.session_state.theme == "light" else 1)
if theme.lower() != st.session_state.theme:
    st.session_state.theme = theme.lower()
    st.rerun() # Rerun to apply theme immediately

# Role selection (for future advanced features)
st.session_state.role = st.sidebar.selectbox("Role", ["admin", "user"], index=0 if st.session_state.role == "admin" else 1)

# Apply dark theme CSS
if st.session_state.theme == "dark":
    st.markdown("""
        <style>
        .stApp { background-color: #0f1a44; color: #ffffff; }
        .stSidebar { background-color: #1a2a6c; border-right: 1px solid #3b4a8b; }
        .stTextInput > div > input, .stSelectbox > div > select, .stTextArea > div > textarea { background-color: #2a3a7b; color: #ffffff; border: 1px solid #3b4a8b; }
        .stTextInput > div > input:focus, .stSelectbox > div > select:focus, .stTextArea > div > textarea:focus { border-color: #ff6200; box-shadow: 0 0 0 2px rgba(255, 98, 0, 0.3); }
        .stButton > button { background-color: #0073bb; }
        .stButton > button:hover { background-color: #005ea2; }
        .stButton > button.secondary { background-color: #2a3a7b; color: #ffffff; border: 1px solid #3b4a8b; }
        .stButton > button.secondary:hover { background-color: #3b4a8b; }
        .stExpander { background-color: #1a2a6c; border: 1px solid #3b4a8b; }
        .stTable { background-color: #1a2a6c; border: 1px solid #3b4a8b; }
        .stTable th { background-color: #3b4a8b; color: #ffffff; }
        .stTable td { color: #ffffff; }
        .aws-button { background-color: #0073bb; }
        .aws-button:hover { background-color: #005ea2; }
        h1, h2, h3 { color: #ffffff; }
        .aws-divider { border-top: 1px solid #3b4a8b; }
        </style>
    """, unsafe_allow_html=True)

# Interactive Tutorial
def show_tutorial():
    st.sidebar.markdown('<h2 style="color: #0f1a44;">Tutorial: Learn Threat Modeling</h2>', unsafe_allow_html=True)
    tutorial_steps = [
        {
            "title": "What is Threat Modeling?",
            "content": "Threat modeling identifies security risks in a system using the STRIDE framework (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege). Start by creating a Data Flow Diagram (DFD).",
            "action": "Go to 'Create Model' and select the 'Web Application' template."
        },
        {
            "title": "Building a DFD",
            "content": "A DFD includes Processes (e.g., servers), Data Stores (e.g., databases), External Entities (e.g., users), and Data Flows (e.g., HTTP requests). Drag elements onto the canvas and connect them with Data Flows.",
            "action": "Add a Process and a Data Flow in the DFD editor."
        },
        {
            "title": "Identifying Threats",
            "content": "The app uses STRIDE to suggest threats based on your DFD and architecture. For example, a database may face Information Disclosure risks like SQL injection.",
            "action": "Enter a system description (e.g., 'web app with database') and click 'Generate'."
        },
        {
            "title": "Review and Mitigate",
            "content": "Review generated threats, their risks, and mitigations. Download reports to document your findings.",
            "action": "Download a PDF report and review the mitigations."
        }
    ]
    step = st.session_state.tutorial_step
    if step < len(tutorial_steps):
        with st.sidebar.expander(tutorial_steps[step]["title"], expanded=True):
            st.write(tutorial_steps[step]["content"])
            if st.button("Next Step", key="tutorial_next"):
                st.session_state.tutorial_step += 1
                st.rerun()
    else:
        st.sidebar.success("Tutorial completed! Explore the app or take the quiz.")

# STRIDE Explanations
def show_stride_info():
    st.markdown('<h2 style="color: #0f1a44;">Understanding STRIDE</h2>', unsafe_allow_html=True)
    st.markdown('<div class="aws-divider"></div>', unsafe_allow_html=True)
    for category, threats in stride_library.items():
        with st.expander(category):
            st.markdown(f"<p><strong>Description</strong>: {threats[0]['threat']}</p>", unsafe_allow_html=True)
            st.markdown(f"<p><strong>Vulnerability</strong>: {threats[0]['vulnerability']}</p>", unsafe_allow_html=True)
            st.markdown(f"<p><strong>Risk</strong>: {threats[0]['risk']}</p>", unsafe_allow_html=True)
            st.markdown(f"<p><strong>Mitigation</strong>: {threats[0]['mitigation']}</p>", unsafe_allow_html=True)
            st.markdown(f"<p><strong>Compliance</strong>: {threats[0]['compliance']}</p>", unsafe_allow_html=True)
            st.markdown(f"<p><strong>Example</strong>: {threats[0]['example']}</p>", unsafe_allow_html=True)

# Quiz Mode
def show_quiz():
    st.markdown('<h2 style="color: #0f1a44;">Test Your Knowledge</h2>', unsafe_allow_html=True)
    st.markdown('<div class="aws-divider"></div>', unsafe_allow_html=True)
    questions = [
        {
            "question": "What does the 'S' in STRIDE stand for?",
            "options": ["Security", "Spoofing", "System", "Standard"],
            "correct": "Spoofing",
            "explanation": "Spoofing involves impersonating a user or system to gain unauthorized access."
        },
        {
            "question": "Which STRIDE category addresses data exposure?",
            "options": ["Tampering", "Repudiation", "Information Disclosure", "Denial of Service"],
            "correct": "Information Disclosure",
            "explanation": "Information Disclosure involves unauthorized access to sensitive data, like SQL injection."
        },
        {
            "question": "What is a key mitigation for Elevation of Privilege?",
            "options": ["Encryption", "Rate limiting", "Least privilege", "MFA"],
            "correct": "Least privilege",
            "explanation": "Least privilege ensures users have only the permissions needed, reducing escalation risks."
        }
    ]
    with st.container():
        for i, q in enumerate(questions):
            st.markdown(f"<h3 style='color: #0f1a44;'>Question {i+1}: {q['question']}</h3>", unsafe_allow_html=True)
            answer = st.radio(f"Select an answer for question {i+1}", q["options"], key=f"quiz_q{i}", label_visibility="collapsed")
            st.session_state.quiz_answers[f"q{i}"] = answer
        if st.button("Submit Quiz"):
            score = sum(1 for i, q in enumerate(questions) if st.session_state.quiz_answers.get(f"q{i}") == q["correct"])
            st.markdown(f"<p><strong>Score</strong>: {score}/{len(questions)}</p>", unsafe_allow_html=True)
            for i, q in enumerate(questions):
                if st.session_state.quiz_answers.get(f"q{i}") != q["correct"]:
                    st.markdown(f"<p><strong>Question {i+1}</strong>: Incorrect. {q['explanation']}</p>", unsafe_allow_html=True)
            st.session_state.quiz_answers = {} # Clear answers after submission
            logger.info(f"Quiz completed with score: {score}/{len(questions)}")

# Main app navigation
options = ["Tutorial", "STRIDE Info", "Pre-defined Models", "Create Model", "Saved Models", "Quiz", "Logout"]
if st.session_state.role == "admin":
    options.append("Manage Users (Admin Only)") # Placeholder for future admin features
option = st.sidebar.radio("Navigation", options, label_visibility="collapsed")

# Display User ID in sidebar if authenticated
if st.session_state.user_id:
    st.sidebar.markdown(f"**Logged in as:** `{st.session_state.user_id}`")
else:
    st.sidebar.info("Authenticating user...")

# --- Firebase Communication Setup ---
# Hidden text area to receive user_id from JavaScript
st.markdown(
    """
    <style>
    .stTextArea[data-testid="stTextArea-firebase-init-data"] {
        display: none;
    }
    </style>
    """,
    unsafe_allow_html=True,
)
firebase_init_data_transfer = st.text_area(
    "firebase_init_data",
    value=json.dumps({"user_id": st.session_state.user_id}), # Send current user_id (might be None initially)
    height=68,
    key="streamlit_firebase_init_data", # This key is used by JS to send data
    help="Do not modify this field directly.",
)

# Process Firebase init data received from JavaScript
if firebase_init_data_transfer:
    try:
        init_data = json.loads(firebase_init_data_transfer)
        if init_data.get('user_id') and init_data['user_id'] != st.session_state.user_id:
            st.session_state.user_id = init_data['user_id']
            # We don't get the actual DB/Auth objects, but we know they are initialized on JS side
            st.session_state.db = True 
            st.session_state.auth = True
            logger.info(f"User authenticated: {st.session_state.user_id}")
            st.rerun() # Rerun to update the UI with user_id
    except json.JSONDecodeError:
        logger.error("Error decoding Firebase init data from JS.")

# Hidden text area for JS to send save/delete confirmations or trigger loads
st.markdown(
    """
    <style>
    .stTextArea[data-testid="stTextArea-js-commands"] {
        display: none;
    }
    </style>
    """,
    unsafe_allow_html=True,
)
js_commands_output = st.text_area(
    "js_commands_output",
    value="",
    height=68,
    key="streamlit_js_commands",
    help="Do not modify this field directly.",
)

# Process commands from JS
if js_commands_output:
    try:
        command = json.loads(js_commands_output)
        if command.get("action") == "model_saved":
            st.success(f"Model '{command['model_name']}' successfully saved to cloud!")
            logger.info(f"Model saved: {command['model_name']}")
            st.session_state.streamlit_js_commands = "" # Clear to prevent re-processing
            st.rerun()
        elif command.get("action") == "model_deleted":
            st.success(f"Model '{command['model_id']}' successfully deleted from cloud!")
            logger.info(f"Model deleted: {command['model_id']}")
            st.session_state.streamlit_js_commands = "" # Clear to prevent re-processing
            st.rerun()
        elif command.get("action") == "load_models_response":
            # This is handled by load_models_data_transfer directly, but good for debugging
            pass
        elif command.get("action") == "error":
            st.error(f"JS Error: {command.get('message', 'Unknown error')}")
            logger.error(f"JS Error: {command.get('message', 'Unknown error')}")
            st.session_state.streamlit_js_commands = ""
        st.session_state.streamlit_js_commands = "" # Ensure it's cleared after processing
    except json.JSONDecodeError:
        logger.error("Error decoding command from JS.")
        st.error("Error processing JS command.")

# Hidden text area to send commands to JavaScript (e.g., save, load, delete requests)
st.markdown(
    """
    <style>
    .stTextArea[data-testid="stTextArea-js-requests"] {
        display: none;
    }
    </style>
    """,
    unsafe_allow_html=True,
)
js_request_data = {}
if st.session_state.get('js_save_request'):
    js_request_data['save'] = st.session_state.js_save_request
    st.session_state.js_save_request = None # Clear request after sending
if st.session_state.get('js_load_request'):
    js_request_data['load'] = True
    st.session_state.js_load_request = False # Clear request after sending
if st.session_state.get('js_delete_request'):
    js_request_data['delete'] = st.session_state.js_delete_request
    st.session_state.js_delete_request = None # Clear request after sending

st.text_area(
    "js_requests_input",
    value=json.dumps(js_request_data),
    height=68,
    key="streamlit_js_requests",
    help="Do not modify this field directly.",
)
# --- End Firebase Communication Setup ---

if option == "Tutorial":
    show_tutorial()

elif option == "STRIDE Info":
    show_stride_info()

elif option == "Logout":
    st.session_state.clear()
    st.session_state.role = "admin"
    st.session_state.tutorial_step = 0
    logger.info("User logged out")
    st.rerun()

elif option == "Pre-defined Models":
    st.markdown('<h2 style="color: #0f1a44;">Pre-defined Threat Models</h2>', unsafe_allow_html=True)
    st.markdown('<div class="aws-divider"></div>', unsafe_allow_html=True)
    for model in pre_defined_threat_models:
        with st.expander(model["name"]):
            st.markdown(f"<p><strong>Architecture</strong>: {model['architecture']}</p>", unsafe_allow_html=True)
            st.markdown("<p><strong>Threats</strong>:</p>", unsafe_allow_html=True)
            st.table([
                {k: v for k, v in threat.items() if k in ["threat", "vulnerability", "risk", "mitigation", "compliance", "example"]}
                for threat in model["threats"]
            ])
            st.plotly_chart(create_risk_chart(model["threats"], datetime.now().timestamp()))
            
            # Use the DFD elements from the pre-defined model to generate a temporary image for PDF
            # Note: This is a simplification. A full DFD rendering would require the JS component.
            # For demonstration, we'll use a placeholder or assume the DFD image can be generated.
            # For this context, we'll pass the DFD elements to the PDF function, but the image
            # itself would need to be generated by the JS DFD editor.
            # Since the JS DFD editor is not part of this Python file, we can't generate the image directly.
            # We'll pass `None` for the image for pre-defined models, or use a dummy image if available.
            
            col1, col2, col3 = st.columns([1, 1, 1])
            with col1:
                st.markdown(create_json_report(model["name"], model["architecture"], model["dfd_elements"], model["threats"], datetime.now().timestamp()), unsafe_allow_html=True)
            with col2:
                st.markdown(create_csv_report(model["name"], model["threats"], datetime.now().timestamp()), unsafe_allow_html=True)
            with col3:
                # For pre-defined models, dfd_image is not readily available from the Python side
                # If a static image for each pre-defined model existed, it could be passed here.
                st.markdown(create_pdf_report(model["name"], model["architecture"], model["dfd_elements"], model["threats"], None, datetime.now().timestamp()), unsafe_allow_html=True)

elif option == "Create Model":
    st.markdown('<h2 style="color: #0f1a44;">Create Threat Model</h2>', unsafe_allow_html=True)
    st.markdown("Drag Processes, Data Stores, or External Entities to create a DFD. Use templates to start quickly.")
    st.markdown('<div class="aws-divider"></div>', unsafe_allow_html=True)

    # Template selection
    col1, col2 = st.columns([2, 1])
    with col1:
        template = st.selectbox("DFD Template", ["None"] + list(dfd_templates.keys()))
    with col2:
        if st.button("Load Template", type="secondary"):
            if template != "None":
                st.session_state.dfd_elements = dfd_templates[template]
                st.session_state.last_update = datetime.now().timestamp()
                st.session_state.dfd_image = None # Clear image on new template load
                logger.info(f"Loaded DFD template: {template}")
                st.rerun() # Rerun to update DFD editor with new elements

    # DFD editor HTML content
    # Read the HTML file and replace placeholders
    try:
        with open("dfd_editor.html", "r") as f:
            dfd_editor_html_template = f.read()

        # Replace placeholders with actual values
        dfd_editor_html_content = dfd_editor_html_template.replace(
            "{{THEME_PLACEHOLDER_BG}}", '#0f1a44' if st.session_state.theme == 'dark' else '#f8f9fa'
        ).replace(
            "{{THEME_PLACEHOLDER_CONTAINER_BG}}", '#1a2a6c' if st.session_state.theme == 'dark' else '#ffffff'
        ).replace(
            "{{THEME_PLACEHOLDER}}", st.session_state.theme
        ).replace(
            "{{APP_ID_PLACEHOLDER}}", st.session_state.app_id
        ).replace(
            "{{FIREBASE_CONFIG_JSON_PLACEHOLDER}}", st.session_state.firebase_config_json
        ).replace(
            "{{INITIAL_AUTH_TOKEN_PLACEHOLDER}}", json.dumps(st.session_state.initial_auth_token)
        ).replace(
            "{{DFD_ELEMENTS_PLACEHOLDER}}", json.dumps(st.session_state.dfd_elements)
        )

    except FileNotFoundError:
        st.error("Error: dfd_editor.html not found. Please ensure the file is in the project directory.")
        logger.error("dfd_editor.html not found")
        dfd_editor_html_content = "" # Set to empty to avoid further errors
    except Exception as e:
        st.error(f"Error preparing DFD editor HTML: {e}")
        logger.error(f"Error preparing DFD editor HTML: {e}")
        dfd_editor_html_content = ""


    col1, col2 = st.columns([3, 2])
    with col1:
        # DFD editor component
        dfd_data = components.html(dfd_editor_html_content, height=450, key="dfd_editor_component")

    # Hidden text area to receive DFD data from JavaScript
    st.markdown(
        """
        <style>
        .stTextArea[data-testid="stTextArea-dfd-data"] {
            display: none;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    dfd_data_transfer_widget_value = st.text_area(
        "dfd_data_transfer",
        value=json.dumps({"elements": st.session_state.dfd_elements, "selected": None, "image": None}),
        height=68,
        key="streamlit_dfd_data", # This key is used by JS to find the element
        help="Do not modify this field directly.",
    )

    # Process DFD data received from JavaScript
    if dfd_data_transfer_widget_value:
        try:
            received_dfd_data = json.loads(dfd_data_transfer_widget_value)
            # Only update if the data actually changed to prevent infinite loops and unnecessary reruns
            if received_dfd_data.get("elements") != st.session_state.dfd_elements:
                st.session_state.dfd_elements = received_dfd_data.get("elements", [])
                st.session_state.last_update = datetime.now().timestamp()
                logger.info("DFD elements updated from JS.")
            
            if received_dfd_data.get("image") and received_dfd_data["image"] != st.session_state.dfd_image:
                try:
                    # DFD image is SVG base64, need to convert to PNG for PDF reportlab
                    # This conversion is complex and best done with a dedicated library if not in browser
                    # For now, we'll store the SVG base64 and handle conversion in PDF report if possible
                    st.session_state.dfd_image = base64.b64decode(received_dfd_data["image"].split(",")[1])
                except Exception as e:
                    logger.error(f"Error decoding DFD image from JS: {e}")
                    st.session_state.dfd_image = None

            # Handle selected element from DFD editor for annotation
            if received_dfd_data.get("selected"):
                selected_id_from_js = received_dfd_data["selected"]
                st.session_state.selected_dfd_element = next((e for e in st.session_state.dfd_elements if e["id"] == selected_id_from_js), None)
            else:
                st.session_state.selected_dfd_element = None

        except json.JSONDecodeError:
            st.error("Error decoding DFD data from editor.")
            logger.error("JSONDecodeError for DFD data.")
        except Exception as e:
            st.error(f"An unexpected error occurred while processing DFD data: {e}")
            logger.error(f"Unexpected error processing DFD data: {e}")


    # Annotate elements
    with col2:
        if st.session_state.selected_dfd_element:
            selected_element = st.session_state.selected_dfd_element
            st.markdown(f"<p><strong>Editing: {selected_element['name']} ({selected_element['type']})</strong></p>", unsafe_allow_html=True)
            
            with st.form(key=f"edit_dfd_element_{selected_element['id']}", clear_on_submit=False):
                element_name = st.text_input("Name", value=selected_element["name"])
                technology = st.text_input("Technology", value=selected_element.get("technology", ""))
                data_flow_type = ""
                if selected_element["type"] == "Data Flow":
                    data_flow_type = st.text_input("Data Flow Type", value=selected_element.get("data_flow", ""))
                
                if st.form_submit_button("Update Element Details"):
                    valid_name, name_error = validate_input(element_name, "Name")
                    if valid_name:
                        for elem in st.session_state.dfd_elements:
                            if elem["id"] == selected_element["id"]:
                                elem["name"] = element_name
                                elem["technology"] = technology
                                if elem["type"] == "Data Flow":
                                    elem["data_flow"] = data_flow_type
                                break
                        st.success("Element updated! Refreshing DFD...")
                        st.session_state.last_update = datetime.now().timestamp() # Trigger re-render
                        st.rerun()
                    else:
                        st.error(name_error)
        else:
            st.info("Select a DFD element on the left to edit its properties.")

    # Display DFD elements in a table
    if st.session_state.dfd_elements:
        st.markdown('<h3 style="color: #0f1a44;">Current DFD Elements</h3>', unsafe_allow_html=True)
        dfd_table_data = []
        for elem in st.session_state.dfd_elements:
            row = {"Type": elem["type"], "Name": elem["name"], "Technology": elem.get("technology", "")}
            if elem["type"] == "Data Flow":
                source_name = next((e['name'] for e in st.session_state.dfd_elements if e['id'] == elem['source']), 'N/A')
                target_name = next((e['name'] for e in st.session_state.dfd_elements if e['id'] == elem['target']), 'N/A')
                row["Data Flow"] = f"{source_name} -> {target_name} ({elem.get('data_flow', '')})"
            else:
                row["Data Flow"] = ""
            dfd_table_data.append(row)
        st.table(pd.DataFrame(dfd_table_data))

    # Generate threat model
    with st.container():
        st.markdown('<h3 style="color: #0f1a44;">Generate Threat Model</h3>', unsafe_allow_html=True)
        threat_model_name = st.text_input("Threat Model Name", placeholder="e.g., My Banking App Threat Model")
        architecture_description = st.text_area("System Architecture Description", placeholder="Describe your system (e.g., web app with database, mobile app, IoT system)")
        
        if st.button("Generate Threat Model", type="primary"):
            validations = [
                validate_input(threat_model_name, "Threat Model Name"),
                validate_input(architecture_description, "Architecture Description"),
                validate_dfd(st.session_state.dfd_elements)
            ]
            
            error_messages = [error for valid, error in validations if not valid]
            
            if error_messages:
                for error in error_messages:
                    st.error(error)
                logger.warning(f"Threat model generation failed due to validation errors: {'; '.join(error_messages)}")
            else:
                with st.spinner("Generating threats..."):
                    generated_threats = generate_threat_model_logic(st.session_state.dfd_elements, architecture_description, stride_library)
                
                st.session_state.threat_model = {
                    "name": threat_model_name,
                    "architecture": architecture_description,
                    "dfd_elements": st.session_state.dfd_elements,
                    "threats": generated_threats
                }
                
                st.markdown(f"<h3 style='color: #0f1a44;'>Threat Model: {threat_model_name}</h3>", unsafe_allow_html=True)
                st.markdown(f"<p><strong>Architecture</strong>: {architecture_description}</p>", unsafe_allow_html=True)
                
                if st.session_state.dfd_image:
                    st.image(st.session_state.dfd_image, caption="Generated DFD Diagram")
                else:
                    st.warning("DFD image could not be generated. Please ensure the DFD editor is interactive.")

                st.markdown("<p><strong>DFD Elements</strong>:</p>", unsafe_allow_html=True)
                st.table(pd.DataFrame(dfd_table_data)) # Reuse the already prepared DFD table data
                
                st.markdown("<p><strong>Threats Identified</strong>:</p>", unsafe_allow_html=True)
                if generated_threats:
                    st.table(pd.DataFrame([
                        {k: v for k, v in threat.items() if k in ["threat", "vulnerability", "risk", "mitigation", "compliance", "example"]}
                        for threat in generated_threats
                    ]))
                    timestamp = datetime.now().timestamp()
                    st.plotly_chart(create_risk_chart(generated_threats, timestamp))
                    
                    col_reports = st.columns(3)
                    with col_reports[0]:
                        st.markdown(create_json_report(threat_model_name, architecture_description, st.session_state.dfd_elements, generated_threats, timestamp), unsafe_allow_html=True)
                    with col_reports[1]:
                        st.markdown(create_csv_report(threat_model_name, generated_threats, timestamp), unsafe_allow_html=True)
                    with col_reports[2]:
                        st.markdown(create_pdf_report(threat_model_name, architecture_description, st.session_state.dfd_elements, generated_threats, st.session_state.dfd_image, timestamp), unsafe_allow_html=True)
                    
                    # Trigger save to Firestore
                    if st.session_state.firebase_initialized and st.session_state.user_id:
                        st.session_state.js_save_request = {
                            "model_name": threat_model_name,
                            "architecture": architecture_description,
                            "dfd_elements": st.session_state.dfd_elements,
                            "threats": generated_threats
                        }
                        st.info("Saving model to cloud...")
                        logger.info(f"Save request queued for model: {threat_model_name}")
                    else:
                        st.warning("Not logged in. Model will not be saved to cloud. Please authenticate to enable persistence.")
                else:
                    st.info("No threats were generated based on your DFD and architecture description.")

elif option == "Saved Models":
    st.markdown('<h2 style="color: #0f1a44;">Saved Threat Models</h2>', unsafe_allow_html=True)
    st.markdown('<div class="aws-divider"></div>', unsafe_allow_html=True)

    if not st.session_state.firebase_initialized or not st.session_state.user_id:
        st.info("Please log in or wait for authentication to view saved models.")
    else:
        # Hidden text area to receive loaded models data from JavaScript
        st.markdown(
            """
            <style>
            .stTextArea[data-testid="stTextArea-load-models"] {
                display: none;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )
        load_models_data_transfer = st.text_area(
            "load_models_data",
            value=json.dumps([]), # Initial empty list
            height=68,
            key="streamlit_load_models_data", # This key is used by JS to send data
            help="Do not modify this field directly.",
        )

        # Trigger JS to load models when this section is visible
        if st.session_state.user_id and not st.session_state.js_load_request: # Only trigger if user is authenticated and not already requested
            st.session_state.js_load_request = True
            st.info("Loading saved models from cloud...")
            logger.info("Load models request sent to JS.")
            # Rerun is handled by the JS response updating load_models_data_transfer

        saved_models_list = []
        if load_models_data_transfer:
            try:
                loaded_models_raw = json.loads(load_models_data_transfer)
                # Ensure dfd_elements and threats are parsed back from string
                for m in loaded_models_raw:
                    m['dfd_elements'] = json.loads(m.get('dfd_elements', '[]'))
                    m['threats'] = json.loads(m.get('threats', '[]'))
                    m['display_name'] = f"{m['model_name']} (Last Updated: {datetime.fromisoformat(m['last_updated']).strftime('%Y-%m-%d %H:%M')})"
                saved_models_list = loaded_models_raw
            except json.JSONDecodeError as e:
                st.error(f"Error decoding loaded models data: {e}")
                logger.error(f"JSONDecodeError loading models: {e}")
            except Exception as e:
                st.error(f"An unexpected error occurred while processing loaded models: {e}")
                logger.error(f"Unexpected error processing loaded models: {e}")
        
        if saved_models_list:
            selected_model_display_name = st.selectbox(
                "Select a model to load or delete:",
                ["-- Select a saved model --"] + [m['display_name'] for m in saved_models_list],
                key="load_model_select"
            )

            if selected_model_display_name != "-- Select a saved model --":
                selected_model_obj = next((m for m in saved_models_list if m['display_name'] == selected_model_display_name), None)
                if selected_model_obj:
                    st.markdown(f"#### Details for: {selected_model_obj['model_name']}")
                    st.markdown(f"**Architecture**: {selected_model_obj['architecture']}")
                    st.markdown(f"**Created At**: {datetime.fromisoformat(selected_model_obj['created_at']).strftime('%Y-%m-%d %H:%M:%S')}")
                    st.markdown(f"**Last Updated**: {datetime.fromisoformat(selected_model_obj['last_updated']).strftime('%Y-%m-%d %H:%M:%S')}")

                    st.markdown("<p><strong>DFD Elements</strong>:</p>", unsafe_allow_html=True)
                    dfd_table_data_loaded = []
                    for elem in selected_model_obj['dfd_elements']:
                        row = {"Type": elem["type"], "Name": elem["name"], "Technology": elem.get("technology", "")}
                        if elem["type"] == "Data Flow":
                            source_name = next((e['name'] for e in selected_model_obj['dfd_elements'] if e['id'] == elem['source']), 'N/A')
                            target_name = next((e['name'] for e in selected_model_obj['dfd_elements'] if e['id'] == elem['target']), 'N/A')
                            row["Data Flow"] = f"{source_name} -> {target_name} ({elem.get('data_flow', '')})"
                        else:
                            row["Data Flow"] = ""
                        dfd_table_data_loaded.append(row)
                    st.table(pd.DataFrame(dfd_table_data_loaded))

                    st.markdown("<p><strong>Threats</strong>:</p>", unsafe_allow_html=True)
                    st.table(pd.DataFrame([
                        {k: v for k, v in threat.items() if k in ["threat", "vulnerability", "risk", "mitigation", "compliance", "example"]}
                        for threat in selected_model_obj['threats']
                    ]))
                    st.plotly_chart(create_risk_chart(selected_model_obj['threats'], datetime.now().timestamp()))

                    col_load_buttons = st.columns(2)
                    with col_load_buttons[0]:
                        if st.button(f"📥 Load '{selected_model_obj['model_name']}' into editor"):
                            st.session_state.dfd_elements = selected_model_obj['dfd_elements']
                            # Note: dfd_image cannot be directly loaded back from Firestore as it's a snapshot
                            st.session_state.dfd_image = None # Clear existing image
                            st.session_state.threat_model = {
                                "name": selected_model_obj['model_name'],
                                "architecture": selected_model_obj['architecture'],
                                "dfd_elements": selected_model_obj['dfd_elements'],
                                "threats": selected_model_obj['threats']
                            }
                            st.success(f"Model '{selected_model_obj['model_name']}' loaded successfully into 'Create Model' section!")
                            logger.info(f"Model loaded: {selected_model_obj['model_name']}")
                            st.rerun()
                    with col_load_buttons[1]:
                        if st.button(f"🗑️ Delete '{selected_model_obj['model_name']}'", key=f"delete_model_{selected_model_obj['id']}"):
                            st.session_state.js_delete_request = selected_model_obj['id']
                            st.info(f"Request to delete '{selected_model_obj['model_name']}' sent.")
                            logger.info(f"Delete request queued for model: {selected_model_obj['id']}")
                            # Rerun will be triggered by JS command output

                else:
                    st.error("Selected model not found.")
        else:
            st.info("No saved models found for this user. Create and save a model first!")
    
elif option == "Quiz":
    show_quiz()

elif option == "Manage Users (Admin Only)":
    st.markdown('<h2 style="color: #0f1a44;">User Management (Admin Only)</h2>', unsafe_allow_html=True)
    st.markdown('<div class="aws-divider"></div>', unsafe_allow_html=True)
    if st.session_state.role == "admin":
        st.info("This section is for managing users and roles in a full commercial deployment. Features like user creation, role assignment, and audit logs would be here.")
        st.write(f"Current User ID: `{st.session_state.user_id}`")
        # Placeholder for future admin features
        st.warning("User management features are not yet implemented in this demo.")
    else:
        st.warning("You do not have permission to access this section.")
