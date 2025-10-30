#!/usr/bin/env python3
# core/crawler.py

import requests
import time
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from collections import deque
import random

class Crawler:
    """
    An intelligent web crawler designed for security reconnaissance.
    It discovers URLs, forms, and potential parameters while being respectful to the target.
    """
    def __init__(self, base_url, session, config):
        self.base_url = base_url
        self.session = session
        self.config = config
        self.domain = urlparse(base_url).netloc
        self.visited_urls = set()
        self.discovered_urls = set([base_url])
        self.forms = []
        self.url_queue = deque([base_url])
        self.robots_txt_cache = {}

    def _is_valid_url(self, url):
        """Check if URL is within scope and not a common file type."""
        try:
            parsed = urlparse(url)
            if parsed.netloc != self.domain:
                return False
            
            # Avoid common static files and binary content
            if re.search(r'\.(css|js|jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot|pdf|zip|tar|gz)$', parsed.path, re.IGNORECASE):
                return False
            
            return True
        except Exception:
            return False

    def _can_fetch(self, url):
        """Check robots.txt for crawling restrictions."""
        try:
            parsed_url = urlparse(url)
            robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"

            if robots_url not in self.robots_txt_cache:
                try:
                    response = self.session.get(robots_url, timeout=5)
                    self.robots_txt_cache[robots_url] = response.text
                except requests.RequestException:
                    self.robots_txt_cache[robots_url] = "" # No robots.txt or error
            
            robots_content = self.robots_txt_cache[robots_url]
            user_agent = "*"
            
            # Simple parsing of robots.txt
            for line in robots_content.splitlines():
                if line.lower().startswith("user-agent:"):
                    user_agent = line.split(":")[1].strip()
                if user_agent in ["*", self.session.headers['User-Agent']] and line.lower().startswith("disallow:"):
                    disallow_path = line.split(":")[1].strip()
                    if disallow_path and parsed_url.path.startswith(disallow_path):
                        return False
            return True
        except Exception:
            return True # Default to allow if parsing fails

    def _extract_links(self, response, current_url):
        """Extract all valid links from a response."""
        soup = BeautifulSoup(response.text, 'html.parser')
        links = set()
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(current_url, href)
            if self._is_valid_url(full_url):
                links.add(full_url)
        return links

    def _extract_forms(self, response, current_url):
        """Extract all forms from a page, including action, method, and inputs."""
        soup = BeautifulSoup(response.text, 'html.parser')
        page_forms = []
        for form in soup.find_all('form'):
            action = form.get('action')
            method = form.get('method', 'get').lower()
            
            # Resolve relative action URLs
            full_action_url = urljoin(current_url, action) if action else current_url

            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                if input_name:
                    inputs.append({'name': input_name, 'type': input_type})
            
            if inputs: # Only care about forms with inputs
                page_forms.append({
                    'url': full_action_url,
                    'method': method,
                    'inputs': inputs
                })
        return page_forms

    def crawl(self, max_pages=None):
        """
        Main crawling loop.
        Returns a dictionary of discovered assets.
        """
        pages_crawled = 0
        while self.url_queue and (max_pages is None or pages_crawled < max_pages):
            current_url = self.url_queue.popleft()

            if current_url in self.visited_urls or not self._can_fetch(current_url):
                continue

            print(f"[Crawler] Discovering: {current_url}")
            self.visited_urls.add(current_url)
            pages_crawled += 1
            
            try:
                # Rotate User-Agent and add delay for stealth
                self.session.headers.update({'User-Agent': random.choice(self.config['user_agents'])})
                time.sleep(self.config['delay'])
                
                response = self.session.get(current_url, timeout=self.config['timeout'])
                response.raise_for_status() # Will raise an HTTPError for bad responses (4xx or 5xx)

                # Discover new links
                new_links = self._extract_links(response, current_url)
                for link in new_links:
                    if link not in self.visited_urls:
                        self.discovered_urls.add(link)
                        self.url_queue.append(link)
                
                # Discover forms
                self.forms.extend(self._extract_forms(response, current_url))

            except requests.RequestException as e:
                print(f"[Crawler] Error crawling {current_url}: {e}")
                continue
            except Exception as e:
                print(f"[Crawler] An unexpected error occurred at {current_url}: {e}")
                continue
        
        return {
            'urls': list(self.discovered_urls),
            'forms': self.forms
        }
