# Project Setup Guide

## Prerequisites
- Python 3.11+
- Git
- GitHub account

## Installation Steps
1. Clone the repository: `git clone <repository-url>`
2. Create virtual environment: `python -m venv venv`
3. Activate: 
   - Windows: `venv\Scripts\activate`
   - Mac/Linux: `source venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`

## Running the Application
1. **To start the BI Dashboard:**
   Navigate to the `src` folder and run:
   ```bash
   cd src
   streamlit run streamlit_app.py
   ```
2. **To start the API Server:**
   Navigate to the `src` folder and run:
   ```bash
   cd src
   python api.py
   ```

## Data Setup
The primary datasets are located in `data/raw/` and `data/processed/`. The AI models are pre-trained and located in the `models/` directory. No immediate data setup is required to run the dashboard.
