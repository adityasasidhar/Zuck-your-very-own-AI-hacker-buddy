"""
Username and social media OSINT tool.
"""

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from langchain.tools import tool

logger = logging.getLogger('zuck_agent')

# Social platforms to check
PLATFORMS = {
    "github": "https://github.com/{username}",
    "twitter": "https://twitter.com/{username}",
    "instagram": "https://instagram.com/{username}",
    "linkedin": "https://linkedin.com/in/{username}",
    "reddit": "https://reddit.com/user/{username}",
    "medium": "https://medium.com/@{username}",
    "dev.to": "https://dev.to/{username}",
    "hackernews": "https://news.ycombinator.com/user?id={username}",
    "keybase": "https://keybase.io/{username}",
    "gitlab": "https://gitlab.com/{username}",
    "bitbucket": "https://bitbucket.org/{username}",
    "pinterest": "https://pinterest.com/{username}",
    "tumblr": "https://{username}.tumblr.com",
    "flickr": "https://flickr.com/people/{username}",
    "vimeo": "https://vimeo.com/{username}",
    "soundcloud": "https://soundcloud.com/{username}",
    "spotify": "https://open.spotify.com/user/{username}",
    "twitch": "https://twitch.tv/{username}",
    "youtube": "https://youtube.com/@{username}",
    "tiktok": "https://tiktok.com/@{username}",
    "snapchat": "https://snapchat.com/add/{username}",
    "telegram": "https://t.me/{username}",
    "discord": "https://discord.com/users/{username}",
    "slack": "https://{username}.slack.com",
    "patreon": "https://patreon.com/{username}",
    "buymeacoffee": "https://buymeacoffee.com/{username}",
    "ko-fi": "https://ko-fi.com/{username}",
    "producthunt": "https://producthunt.com/@{username}",
    "dribbble": "https://dribbble.com/{username}",
    "behance": "https://behance.net/{username}",
}


def check_platform(platform: str, url: str) -> dict:
    """Check if username exists on a platform."""
    try:
        response = requests.get(
            url,
            timeout=10,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            allow_redirects=True
        )
        
        # Most platforms return 404 for non-existent users
        if response.status_code == 200:
            # Some platforms return 200 but show "user not found" page
            # We'd need platform-specific checks for accuracy
            return {"platform": platform, "url": url, "exists": True, "status": response.status_code}
        else:
            return {"platform": platform, "url": url, "exists": False, "status": response.status_code}
            
    except requests.exceptions.RequestException:
        return {"platform": platform, "url": url, "exists": "unknown", "status": "error"}


@tool
def username_search(username: str) -> str:
    """
    Search for a username across multiple social media platforms.
    
    Checks 30+ platforms for the existence of a username.
    
    Args:
        username: Username to search for
        
    Returns:
        Platforms where the username exists
        
    Examples:
        username_search("johndoe")
        username_search("hacker123")
    """
    try:
        username = username.strip().lower()
        
        results = {
            "username": username,
            "found": [],
            "not_found": [],
            "errors": [],
            "total_checked": len(PLATFORMS)
        }
        
        # Check platforms in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for platform, url_template in PLATFORMS.items():
                url = url_template.format(username=username)
                futures[executor.submit(check_platform, platform, url)] = platform
            
            for future in as_completed(futures):
                result = future.result()
                if result["exists"] == True:
                    results["found"].append({
                        "platform": result["platform"],
                        "url": result["url"]
                    })
                elif result["exists"] == False:
                    results["not_found"].append(result["platform"])
                else:
                    results["errors"].append(result["platform"])
        
        results["total_found"] = len(results["found"])
        
        return json.dumps(results, indent=2)
        
    except Exception as e:
        logger.error(f"Username search error: {e}")
        return f"Error: {str(e)}"


@tool
def email_osint(email: str) -> str:
    """
    Gather information about an email address.
    
    Extracts domain info, checks format validity, and looks up domain.
    
    Args:
        email: Email address to investigate
        
    Returns:
        Information gathered about the email
        
    Examples:
        email_osint("user@example.com")
    """
    import re
    import socket
    
    try:
        email = email.strip().lower()
        
        # Validate email format
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            return json.dumps({"error": "Invalid email format"})
        
        username, domain = email.split("@")
        
        result = {
            "email": email,
            "username": username,
            "domain": domain,
            "domain_info": {},
            "mx_records": [],
            "disposable": False,
            "free_provider": False
        }
        
        # Check if free provider
        free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", 
                         "protonmail.com", "icloud.com", "mail.com", "aol.com"]
        result["free_provider"] = domain in free_providers
        
        # Check if disposable
        disposable_domains = ["tempmail.com", "guerrillamail.com", "10minutemail.com",
                            "mailinator.com", "throwaway.email", "temp-mail.org"]
        result["disposable"] = domain in disposable_domains
        
        # Get MX records
        try:
            import dns.resolver
            mx_answers = dns.resolver.resolve(domain, 'MX')
            for rdata in mx_answers:
                result["mx_records"].append(str(rdata.exchange))
        except:
            pass
        
        # Get domain IP
        try:
            ip = socket.gethostbyname(domain)
            result["domain_info"]["ip"] = ip
        except:
            pass
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        logger.error(f"Email OSINT error: {e}")
        return f"Error: {str(e)}"
