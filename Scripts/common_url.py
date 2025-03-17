import requests
from bs4 import BeautifulSoup
import re

def get_table_urls(wikipedia_url):
    # Send a GET request to fetch the Wikipedia page content
    response = requests.get(wikipedia_url)
    
    if response.status_code != 200:
        print("Failed to retrieve the page.")
        return []
    
    # Parse the HTML content using BeautifulSoup
    soup = BeautifulSoup(response.text, 'html.parser')

    # Find all tables on the page (you can further refine this if needed)
    tables = soup.find_all('table', {'class': 'wikitable'})  # Common class for tables in Wikipedia articles

    # Set to store unique URLs and domain names
    urls = set()

    # Loop through all the tables and extract URLs and domains
    for table in tables:
        # Loop through all table rows (tr) in the table
        rows = table.find_all('tr')
        for row in rows:
            # Extract all the anchor tags with href attributes inside the row
            links = row.find_all('a', href=True)
            for link in links:
                url = link['href']
                
                # Case 1: If the URL starts with "http://" or "https://", directly add it
                if re.match(r'https?://', url):
                    urls.add(url)
            
            # Case 2: Search for domains like google.com, example.com in the row itself (not in anchor tags)
            text = row.get_text()
            domain_matches = re.findall(r'\b[A-Za-z0-9.-]+\.[a-z]{2,}\b', text)
            for domain in domain_matches:
                # Add the domain with https:// if it's not already prefixed with http(s)://
                if not re.match(r'https?://', domain):
                    full_url = 'https://' + domain
                    urls.add(full_url)

    return list(urls)
def main():
    url = "https://en.wikipedia.org/wiki/List_of_most-visited_websites"
    
    # Fetch URLs from the Wikipedia page
    urls = get_table_urls(url)

    # Check if URLs were found
    if not urls:
        print("No URLs found, please make sure the Wikipedia page is available.")
        return

    with open('url_file.txt', 'w') as f:
        for u in urls:
            f.write(u + '\n')

    print(f"URLs have been saved to 'url_file.txt'.")

if __name__ == '__main__':
    main()








