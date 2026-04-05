from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sys
import os

# Ensure the local modules can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sentinurl import predict_ultimate

app = FastAPI(title="SentinURL API", description="Phishing Detection API for Chrome Extension")

# Allow requests from the Chrome Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Since it's an extension, allow all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

@app.post("/scan")
async def scan_url(request: URLRequest):
    if not request.url:
        raise HTTPException(status_code=400, detail="URL is required")
        
    try:
        # Run predict_ultimate
        # returns: (lbl, score, src, all_reasons, p1, p2, whois_data, geo_info, neural_analysis)
        result = predict_ultimate(request.url)
        
        lbl, score, src, reasons, p1, p2, whois_data, geo_info, neural_analysis = result
        
        return {
            "status": "success",
            "data": {
                "label": lbl,
                "score": round(score, 4),
                "decision_by": src,
                "reasons": reasons,
                "stage1_prob": round(p1, 4) if p1 is not None else 0,
                "stage2_prob": round(p2, 4) if p2 is not None else 0,
                "whois": whois_data,
                "geo": geo_info,
                "neural_analysis": neural_analysis
            }
        }
    except Exception as e:
        import traceback
        print(f"Error scanning URL: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    # Start the server (Reads PORT from Render.com env, defaults to 8345 locally)
    port = int(os.environ.get("PORT", 8345))
    uvicorn.run("api:app", host="0.0.0.0", port=port, reload=False)
