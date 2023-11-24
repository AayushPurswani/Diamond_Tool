import cv2
import pytesseract
from pdf2image import convert_from_path


def extract_text(image_path, x,y,w,h):
    
    image = cv2.imread(image_path)

    # Crop the region of interest (ROI)
    roi = image[y:y+h, x:x+w]

    # Convert the ROI to grayscale
    gray_roi = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY)

    # Use Tesseract to extract text from the grayscale image
    text = pytesseract.image_to_string(gray_roi)

    return text


def convert_pdf_to_jpg(pdf_path, output_folder, resolution=150):
    images = convert_from_path(pdf_path, dpi=resolution)

    for i, image in enumerate(images):
        image.save(f"{output_folder}/page_{i + 1}.jpg", "JPEG")

