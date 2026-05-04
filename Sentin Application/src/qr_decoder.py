import cv2
import numpy as np

def extract_url_from_qr(image_bytes):
    """
    Decodes a QR code from a raw image byte stream.
    Returns the extracted string (URL) if successful, otherwise None.
    """
    try:
        # Convert bytes to numpy array
        nparr = np.frombuffer(image_bytes, np.uint8)
        
        # Decode image using OpenCV
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if img is None:
            return None, "Failed to decode image file."

        # Initialize the OpenCV QRCode detector
        detector = cv2.QRCodeDetector()
        
        # Detect and decode the QR code
        data, bbox, straight_qrcode = detector.detectAndDecode(img)
        
        if data:
            return data.strip(), None
        else:
            return None, "No valid QR code found in the image."
            
    except Exception as e:
        return None, f"Error processing QR code: {str(e)}"
