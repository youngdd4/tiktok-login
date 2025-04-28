import cloudinary
import cloudinary.uploader
import cloudinary.api
from django.core.files.uploadedfile import UploadedFile, InMemoryUploadedFile
import uuid
import sys

def upload_media(file, resource_type="auto"):
    """
    Upload a file to Cloudinary
    
    Args:
        file: File object from request.FILES or a file path
        resource_type: Type of resource (auto, image, video, raw)
        
    Returns:
        Dictionary containing upload result information including:
        - public_id: Cloudinary public ID
        - secure_url: HTTPS URL to the resource
        - resource_type: Type of resource detected
    """
    try:
        print(f"Upload_media called with file type: {type(file)}, resource_type: {resource_type}", file=sys.stderr)
        
        if isinstance(file, (UploadedFile, InMemoryUploadedFile)):
            # Generate a unique public_id
            public_id = f"tiktok_media/{uuid.uuid4()}"
            print(f"Uploading with public_id: {public_id}", file=sys.stderr)
            
            # Upload to cloudinary
            result = cloudinary.uploader.upload(
                file,
                public_id=public_id,
                resource_type=resource_type,
                overwrite=True
            )
            print(f"Cloudinary upload successful: {result.get('public_id')}", file=sys.stderr)
            return result
        else:
            # For URL or file path
            print(f"Uploading from URL or path", file=sys.stderr)
            result = cloudinary.uploader.upload(
                file,
                resource_type=resource_type,
                overwrite=True
            )
            print(f"Cloudinary URL upload successful: {result.get('public_id')}", file=sys.stderr)
            return result
    except Exception as e:
        print(f"Error in upload_media: {str(e)}", file=sys.stderr)
        # Re-raise to let the caller handle it
        raise

def delete_media(public_id, resource_type="auto"):
    """
    Delete a file from Cloudinary
    
    Args:
        public_id: Cloudinary public ID of the resource
        resource_type: Type of resource (auto, image, video, raw)
        
    Returns:
        Dictionary containing deletion result
    """
    try:
        print(f"Deleting media with public_id: {public_id}", file=sys.stderr)
        result = cloudinary.uploader.destroy(public_id, resource_type=resource_type)
        print(f"Deletion result: {result}", file=sys.stderr)
        return result
    except Exception as e:
        print(f"Error deleting media from Cloudinary: {str(e)}", file=sys.stderr)
        raise

def get_resource_info(public_id, resource_type="auto"):
    """
    Get information about a Cloudinary resource
    
    Args:
        public_id: Cloudinary public ID of the resource
        resource_type: Type of resource (auto, image, video, raw)
        
    Returns:
        Dictionary containing resource information
    """
    return cloudinary.api.resource(public_id, resource_type=resource_type)

def extract_public_id_from_url(url):
    """
    Extract the public_id from a Cloudinary URL
    
    Args:
        url: Cloudinary URL
        
    Returns:
        Public ID as a string or None if not extractable
    """
    if not url or 'res.cloudinary.com' not in url:
        return None
    
    try:
        # Example URL: https://res.cloudinary.com/dbxwjfs6e/image/upload/v1234567890/tiktok_media/abcdef123456
        parts = url.split('/')
        # Find the upload part index
        upload_index = parts.index('upload')
        # The public ID is everything after the version (which follows upload)
        # Skip the version part (v1234567890)
        public_id_parts = parts[upload_index+2:]
        return '/'.join(public_id_parts)
    except (ValueError, IndexError):
        return None 