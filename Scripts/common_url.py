import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin

def get_table_urls(wikipedia_url):
    try:
        # Set a custom user-agent to mimic a real browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Send a GET request to fetch the Wikipedia page content
        response = requests.get(wikipedia_url, headers=headers)

        if response.status_code != 200:
            print("Failed to retrieve the page. Status code:", response.status_code)
            return []

        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all tables on the page with 'wikitable' class
        tables = soup.find_all('table', {'class': 'wikitable'})

        # Set to store unique URLs and domain names
        urls = set()

        # Loop through all the tables and extract URLs and domains
        for table in tables:
            rows = table.find_all('tr')
            for row in rows:
                # Extract all the anchor tags with href attributes inside the row
                links = row.find_all('a', href=True)
                for link in links:
                    url = link['href']

                    # Case 1: If the URL starts with "http://" or "https://", directly add it
                    if re.match(r'https?://', url):
                        urls.add(url)
                    else:
                        # Case 2: If the URL is relative, make it absolute
                        absolute_url = urljoin(wikipedia_url, url)
                        urls.add(absolute_url)

                # Case 2: Search for domains in the row text (not inside anchor tags)
                text = row.get_text()
                domain_matches = re.findall(r'\b[A-Za-z0-9.-]+\.[a-z]{2,}\b', text)
                for domain in domain_matches:
                    # Add the domain with https:// if it's not already prefixed with http(s)://
                    if not re.match(r'https?://', domain):
                        full_url = 'https://' + domain
                        urls.add(full_url)

        return list(urls)
    
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching the page: {e}")
        return []

def main():
    url = "https://en.wikipedia.org/wiki/List_of_most-visited_websites"
    
    # Fetch URLs from the Wikipedia page
    urls = get_table_urls(url)

    # Check if URLs were found
    if not urls:
        print("No URLs found, please make sure the Wikipedia page is available.")
        return

    # Save the URLs to a file
    with open('url_file.txt', 'w') as f:
        for u in urls:
            f.write(u + '\n')

    print(f"URLs have been saved to 'url_file.txt'.")

if __name__ == '__main__':
    main()
