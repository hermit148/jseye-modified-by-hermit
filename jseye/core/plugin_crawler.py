"""Plugin-based crawler for JSEye v2.1."""

import asyncio
import time
from typing import List, Dict, Any, Optional
from .collector import JSCollector
from .js_parser import JSParser
from .wayback import WaybackIntegration
from .gau import GAUIntegration
from .katana import KatanaIntegration
from .subfinder import SubfinderIntegration
from .hakrawler import HakrawlerIntegration
from .linkfinder import LinkFinder
from .headless import HeadlessBrowser
from .utils import calculate_sha256, deduplicate_by_hash, extract_domain
from .logging import get_logger
from .profiling_engine import ProfilingEngine
from .graph_engine import GraphEngine
from ..plugins.manager import PluginManager
from ..plugins.base import PluginContext

logger = get_logger(__name__)


class PluginBasedCrawler:
    """Enhanced crawler using plugin architecture for JSEye v2.1."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.timeout = config.get('timeout', 10)
        self.threads = config.get('threads', 20)
        self.enable_wayback = config.get('wayback', True)
        self.enable_gau = config.get('gau', True)
        self.enable_katana = config.get('katana', True)
        self.enable_subfinder = config.get('subfinder', True)
        self.enable_hakrawler = config.get('hakrawler', True)
        self.enable_headless = config.get('headless', False)
        self.enable_linkfinder = config.get('linkfinder', True)
        self.verbose = config.get('verbose', False)
        self.debug = config.get('debug', False)
        
        # New v2.1 features
        self.enable_profiling = config.get('profile_scan', False)
        self.enable_graph = config.get('generate_graph', False)
        
        # New v3.0 hunter-focused features
        self.actionable_mode = config.get('actionable', False)
        self.aggressive_filter = config.get('aggressive_filter', True)
        self.show_all = config.get('show_all', False)
        
        # Initialize components
        self.js_parser = JSParser()
        self.plugin_manager = PluginManager()
        self.profiling_engine = ProfilingEngine(enabled=self.enable_profiling)
        self.graph_engine = GraphEngine()
        
        # Initialize v3.0 engines
        from .parameter_discovery import ParameterDiscoveryEngine
        from .prioritization import PrioritizationEngine
        self.parameter_engine = ParameterDiscoveryEngine()
        self.prioritization_engine = PrioritizationEngine()
        
        # Results storage
        self.results = {
            'target': '',
            'scan_config': config,
            'scan_metadata': {
                'start_time': None,
                'end_time': None,
                'duration': 0,
                'jseye_version': '3.0.1'
            },
            'js_files': [],
            'plugin_results': {},
            'all_findings': [],
            'endpoints': [],
            'secrets': [],
            'vulnerabilities': [],
            'parameters': [],
            'statistics': {},
            'profiling': {},
            'attack_surface_graph': {},
            'errors': []
        }
    
    async def scan_target(self, target: str) -> Dict[str, Any]:
        """Enhanced scan using plugin architecture."""
        from rich.console import Console
        console = Console()
        
        self.results['target'] = target
        self.results['scan_metadata']['start_time'] = time.time()
        
        try:
            # Start profiling
            self.profiling_engine.start_scan_profiling(target)
            
            logger.info(f"Starting plugin-based scan of {target}")
            
            # Phase 1: JavaScript Collection
            self.profiling_engine.start_operation('js_collection')
            if not self.config.get('silent', False):
                console.print("[cyan]  [*] Collecting JavaScript files...[/cyan]")
            
            js_files = await self._collect_javascript_files(target)
            self.results['js_files'] = js_files
            
            self.profiling_engine.end_operation('js_collection')
            if not self.config.get('silent', False):
                console.print(f"[green]  [+] Collected {len(js_files)} JavaScript files[/green]")
            logger.info(f"Collected {len(js_files)} JavaScript files", target=target, count=len(js_files))
            
            # Phase 2: Load and Configure Plugins
            self.profiling_engine.start_operation('plugin_loading')
            if not self.config.get('silent', False):
                console.print("[cyan]  [*] Loading analysis plugins...[/cyan]")
            
            await self._setup_plugins()
            
            self.profiling_engine.end_operation('plugin_loading')
            
            # Phase 3: Execute Plugins
            self.profiling_engine.start_operation('plugin_execution')
            if not self.config.get('silent', False):
                console.print("[cyan]  [*] Analyzing JavaScript files...[/cyan]")
            
            plugin_results = await self._execute_plugins(target, js_files)
            self.results['plugin_results'] = plugin_results
            
            self.profiling_engine.end_operation('plugin_execution')
            
            # Phase 4: Parameter Discovery (v3.0)
            self.profiling_engine.start_operation('parameter_discovery')
            if self.verbose:
                logger.info("Phase 4: Discovering parameters and endpoints", target=target)
            
            # Extract parameters from JS files and API endpoints
            parameter_results = self.parameter_engine.discover_parameters(
                js_files, 
                self.results.get('all_findings', [])
            )
            
            self.results['parameters'] = parameter_results.get('parameters', [])
            self.results['endpoints'] = parameter_results.get('endpoints', [])
            
            # Merge LinkFinder endpoints
            linkfinder_endpoints = self.results.get('linkfinder_endpoints', [])
            if linkfinder_endpoints:
                # Convert LinkFinder format to standard endpoint format
                for lf_ep in linkfinder_endpoints:
                    endpoint = {
                        'url': lf_ep.get('endpoint', ''),
                        'method': 'GET',
                        'source': 'linkfinder',
                        'type': lf_ep.get('type', 'unknown'),
                        'context': lf_ep.get('context', ''),
                        'source_file': lf_ep.get('source_file', '')
                    }
                    self.results['endpoints'].append(endpoint)
            
            self.profiling_engine.end_operation('parameter_discovery')
            if not self.config.get('silent', False):
                total_params = len(self.results.get('parameters', []))
                total_endpoints = len(self.results.get('endpoints', []))
                console.print(f"[green]  [+] Discovered {total_params} parameters, {total_endpoints} endpoints[/green]")
            
            # Phase 5: Prioritization and Filtering (v3.0)
            self.profiling_engine.start_operation('prioritization')
            if not self.config.get('silent', False):
                console.print("[cyan]  [*] Prioritizing findings...[/cyan]")
            
            # Apply prioritization
            prioritized_results = self.prioritization_engine.prioritize_findings(self.results)
            
            # Apply noise filtering unless show_all is enabled
            if not self.show_all:
                if self.results.get('all_findings'):
                    self.results['all_findings'] = self.prioritization_engine.filter_noise(
                        self.results['all_findings'], 
                        self.aggressive_filter
                    )
                # Don't filter endpoints - they're already valuable
            
            # Store prioritized results
            self.results.update(prioritized_results)
            
            self.profiling_engine.end_operation('prioritization')
            if not self.config.get('silent', False):
                console.print("[green]  [+] Prioritization complete[/green]")
            
            # Phase 6: Consolidate Results
            self.profiling_engine.start_operation('result_consolidation')
            if not self.config.get('silent', False):
                console.print("[cyan]  [*] Consolidating results...[/cyan]")
            
            self._consolidate_plugin_results(plugin_results)
            
            self.profiling_engine.end_operation('result_consolidation')
            
            # Phase 7: Generate Attack Surface Graph (if enabled)
            if self.enable_graph:
                self.profiling_engine.start_operation('graph_generation')
                if not self.config.get('silent', False):
                    console.print("[cyan]  [*] Generating attack surface graph...[/cyan]")
                
                attack_graph = self.graph_engine.generate_attack_surface_graph(self.results)
                self.results['attack_surface_graph'] = {
                    'nodes': [vars(node) for node in attack_graph.nodes],
                    'edges': [vars(edge) for edge in attack_graph.edges],
                    'metadata': attack_graph.metadata,
                    'statistics': attack_graph.statistics
                }
                
                self.profiling_engine.end_operation('graph_generation')
            
            # Phase 8: Generate Statistics and Profiling
            self.profiling_engine.start_operation('statistics_generation')
            if self.verbose:
                logger.info("Phase 8: Generating statistics", target=target)
            
            self._generate_statistics()
            
            if self.enable_profiling:
                scan_profile = self.profiling_engine.generate_scan_profile(target)
                self.results['profiling'] = self.profiling_engine.get_profiling_report()
            
            self.profiling_engine.end_operation('statistics_generation')
            
            # Record completion
            self.results['scan_metadata']['end_time'] = time.time()
            self.results['scan_metadata']['duration'] = (
                self.results['scan_metadata']['end_time'] - 
                self.results['scan_metadata']['start_time']
            )
            
            logger.info("Plugin-based scan completed successfully", 
                       target=target, 
                       duration=self.results['scan_metadata']['duration'],
                       plugins_executed=len(plugin_results),
                       total_findings=len(self.results['all_findings']))
            
            return self.results
            
        except Exception as e:
            error_msg = f"Plugin-based scan failed: {str(e)}"
            self.results['errors'].append(error_msg)
            logger.error(error_msg, target=target, error=str(e))
            
            # Still record timing even on failure
            if self.results['scan_metadata']['start_time']:
                self.results['scan_metadata']['end_time'] = time.time()
                self.results['scan_metadata']['duration'] = (
                    self.results['scan_metadata']['end_time'] - 
                    self.results['scan_metadata']['start_time']
                )
            
            return self.results
    
    async def _collect_javascript_files(self, target: str) -> List[Dict[str, Any]]:
        """Comprehensive JavaScript collection from all sources."""
        from rich.console import Console
        
        all_js_files = []
        all_urls_to_crawl = set()
        console = Console()
        
        # Ensure target has a scheme
        if not target.startswith(('http://', 'https://')):
            target_url = f"https://{target}"
        else:
            target_url = target
        
        domain = extract_domain(target)
        
        # PHASE 1: Subdomain Discovery
        subdomains = [target_url]
        if self.enable_subfinder:
            try:
                console.print(f"[bold cyan]Phase 1:[/bold cyan] Subdomain Discovery")
                subfinder = SubfinderIntegration(timeout=180)
                if subfinder.is_available():
                    discovered_subs = await subfinder.discover_subdomains(domain, silent=True)
                    
                    if discovered_subs:
                        subdomains.extend(discovered_subs)
                        console.print(f"  [green][+][/green] {len(discovered_subs)} subdomains found")
                else:
                    console.print(f"  [yellow][!][/yellow] Subfinder not available")
            except Exception as e:
                console.print(f"  [yellow][!][/yellow] Error: {str(e)[:40]}")
        
        # PHASE 2: URL Discovery from all sources
        console.print(f"\n[bold cyan]Phase 2:[/bold cyan] URL Discovery")
        
        # 2a. GAU - Get All URLs
        if self.enable_gau:
            try:
                gau = GAUIntegration(timeout=120)
                if gau.is_available():
                    gau_urls = await gau.discover_urls(domain, include_subs=True)
                    all_urls_to_crawl.update(gau_urls)
                    console.print(f"  [green][+][/green] GAU: {len(gau_urls)} URLs")
            except Exception:
                pass
        
        # 2b. Wayback Machine
        if self.enable_wayback:
            try:
                async with WaybackIntegration(timeout=60, max_concurrent=10) as wayback:
                    wayback_files = await wayback.discover_historical_js(domain, limit=1000)
                    
                    for wb_file in wayback_files:
                        if wb_file.get('url'):
                            all_urls_to_crawl.add(wb_file['url'])
                        if wb_file.get('content'):
                            js_file = {
                                'url': wb_file['url'],
                                'content': wb_file['content'],
                                'size': wb_file['size'],
                                'hash': calculate_sha256(wb_file['content']),
                                'source': 'wayback',
                                'type': 'historical'
                            }
                            all_js_files.append(js_file)
                    
                    console.print(f"  [green][+][/green] Wayback: {len(wayback_files)} JS files")
            except Exception:
                pass
        
        # 2c. Hakrawler - Deep Web Crawler
        if self.enable_hakrawler:
            try:
                hakrawler = HakrawlerIntegration(timeout=180)
                if hakrawler.is_available():
                    crawled_count = 0
                    js_count = 0
                    # Crawl ALL subdomains for deeper coverage
                    for subdomain in subdomains:
                        try:
                            result = await hakrawler.crawl_with_js_focus(subdomain)
                            if result.get('success'):
                                urls = result.get('urls', [])
                                all_urls_to_crawl.update(urls)
                                crawled_count += len(urls)
                                js_count += len(result.get('js_urls', []))
                        except Exception:
                            continue
                    
                    if crawled_count > 0:
                        console.print(f"  [green][+][/green] Hakrawler: {crawled_count} URLs ({js_count} JS)")
                    else:
                        console.print(f"  [yellow][!][/yellow] Hakrawler: No URLs found")
            except Exception:
                console.print(f"  [yellow][!][/yellow] Hakrawler: Error")
        
        # 2d. Katana - Fast Crawler with JS Support
        if self.enable_katana:
            try:
                katana = KatanaIntegration(timeout=180)
                if katana.is_available():
                    crawled_count = 0
                    js_count = 0
                    # Crawl ALL subdomains for maximum coverage
                    for subdomain in subdomains:
                        try:
                            result = await katana.crawl_with_js_focus(subdomain)
                            if result.get('success'):
                                urls = result.get('urls', [])
                                all_urls_to_crawl.update(urls)
                                crawled_count += len(urls)
                                js_count += len(result.get('js_urls', []))
                        except Exception:
                            continue
                    
                    if crawled_count > 0:
                        console.print(f"  [green][+][/green] Katana: {crawled_count} URLs ({js_count} JS)")
                    else:
                        console.print(f"  [yellow][!][/yellow] Katana: No URLs found")
            except Exception:
                console.print(f"  [yellow][!][/yellow] Katana: Error")
        
        console.print(f"  [bold green]Total:[/bold green] {len(all_urls_to_crawl)} unique URLs")
        
        # PHASE 2.5: Additional Discovery (robots.txt, sitemap, common files)
        console.print(f"\n[bold cyan]Phase 2.5:[/bold cyan] Additional Discovery")
        try:
            from .additional_discovery import AdditionalDiscovery
            
            additional = AdditionalDiscovery(timeout=10)
            
            # Robots.txt discovery
            robots_result = await additional.discover_from_robots_txt(target_url)
            if robots_result.get('success'):
                all_urls_to_crawl.update(robots_result.get('urls', []))
                console.print(f"  [green][+][/green] robots.txt: {robots_result['disallowed_count']} paths")
                
                # Discover from sitemaps
                for sitemap_url in robots_result.get('sitemaps', []):
                    sitemap_urls = await additional.discover_from_sitemap(sitemap_url)
                    all_urls_to_crawl.update(sitemap_urls)
                    if sitemap_urls:
                        console.print(f"  [green][+][/green] Sitemap: {len(sitemap_urls)} URLs")
            
            # Common files discovery
            common_files = await additional.discover_common_files(target_url)
            if common_files:
                all_urls_to_crawl.update(common_files)
                console.print(f"  [green][+][/green] Common files: {len(common_files)} found")
            
            # API documentation discovery
            api_docs = await additional.discover_api_documentation(target_url)
            if api_docs:
                all_urls_to_crawl.update(api_docs)
                console.print(f"  [green][+][/green] API docs: {len(api_docs)} endpoints")
                self.results['api_documentation'] = api_docs
            
        except Exception:
            console.print(f"  [yellow][!][/yellow] Additional discovery failed")
        
        # PHASE 3: Live JS Collection from all subdomains
        console.print(f"\n[bold cyan]Phase 3:[/bold cyan] Live Collection")
        try:
            async with JSCollector(timeout=10, max_concurrent=20) as collector:
                for subdomain in subdomains:
                    try:
                        result = await asyncio.wait_for(
                            collector.collect_from_url(subdomain),
                            timeout=15
                        )
                        if result.get('js_files'):
                            all_js_files.extend(result['js_files'])
                    except (asyncio.TimeoutError, Exception):
                        continue
            
            live_count = len([f for f in all_js_files if f.get('source') != 'wayback'])
            console.print(f"  [green][+][/green] {live_count} live JS files from {len(subdomains)} subdomain(s)")
        except Exception:
            pass
        
        # PHASE 4: Playwright Dynamic JS Discovery
        if self.enable_headless:
            try:
                console.print(f"\n[bold cyan]Phase 4:[/bold cyan] Dynamic Discovery")
                async with HeadlessBrowser() as browser:
                    for subdomain in subdomains[:5]:  # First 5 subdomains
                        try:
                            result = await browser.extract_js_files(subdomain)
                            if result.get('js_files'):
                                all_js_files.extend(result['js_files'])
                        except Exception:
                            continue
                
                dynamic_count = len([f for f in all_js_files if f.get('type') == 'dynamic'])
                console.print(f"  [green][+][/green] {dynamic_count} dynamic JS files")
            except Exception:
                pass
        
        # PHASE 5: Fetch JS from ALL discovered URLs (UNLIMITED)
        console.print(f"\n[bold cyan]Phase 5:[/bold cyan] URL Fetching")
        js_urls = [url for url in all_urls_to_crawl if url.endswith('.js') or '/js/' in url or '.map' in url]
        
        if js_urls:
            try:
                # NO LIMITS - Fetch ALL discovered JS URLs
                console.print(f"  [cyan]Fetching ALL {len(js_urls)} discovered JS URLs...[/cyan]")
                
                async with JSCollector(timeout=10, max_concurrent=100) as collector:  # Increased concurrency
                    for js_url in js_urls:  # NO LIMIT
                        try:
                            result = await asyncio.wait_for(
                                collector.collect_from_url(js_url),
                                timeout=10
                            )
                            if result.get('js_files'):
                                for js_file in result['js_files']:
                                    js_file['source'] = 'discovered_url'
                                    all_js_files.append(js_file)
                        except (asyncio.TimeoutError, Exception):
                            continue
                
                fetched_count = len([f for f in all_js_files if f.get('source') == 'discovered_url'])
                console.print(f"  [green][+][/green] {fetched_count} JS files fetched from {len(js_urls)} URLs")
            except Exception:
                pass
        
        # PHASE 5.5: Recursive JS Discovery (UNLIMITED)
        if all_js_files:
            try:
                console.print(f"\n[bold cyan]Phase 5.5:[/bold cyan] Recursive Discovery")
                from .recursive_js_finder import RecursiveJSFinder
                
                recursive_finder = RecursiveJSFinder()
                recursive_urls = recursive_finder.discover_recursive_js(all_js_files, max_depth=3)  # Increased depth
                
                if recursive_urls:
                    console.print(f"  [cyan]Fetching ALL {len(recursive_urls)} recursively discovered JS files...[/cyan]")
                    # Fetch ALL recursively discovered JS files (NO LIMIT)
                    async with JSCollector(timeout=10, max_concurrent=100) as collector:
                        for rec_url in recursive_urls:  # NO LIMIT
                            try:
                                result = await asyncio.wait_for(
                                    collector.collect_from_url(rec_url),
                                    timeout=10
                                )
                                if result.get('js_files'):
                                    for js_file in result['js_files']:
                                        js_file['source'] = 'recursive'
                                        all_js_files.append(js_file)
                            except (asyncio.TimeoutError, Exception):
                                continue
                    
                    recursive_count = len([f for f in all_js_files if f.get('source') == 'recursive'])
                    console.print(f"  [green][+][/green] {recursive_count} JS files from recursive discovery")
                else:
                    console.print(f"  [yellow][!][/yellow] No recursive JS references found")
            except Exception:
                console.print(f"  [yellow][!][/yellow] Recursive discovery failed")
        
        # PHASE 6: LinkFinder - Extract endpoints from all JS
        if self.enable_linkfinder and all_js_files:
            try:
                console.print(f"\n[bold cyan]Phase 6:[/bold cyan] Endpoint Extraction")
                linkfinder = LinkFinder()
                lf_result = linkfinder.extract_from_multiple(all_js_files)
                
                # Store endpoints in results for later use
                self.results['linkfinder_endpoints'] = lf_result.get('endpoints', [])
                console.print(f"  [green][+][/green] {lf_result['statistics']['total_endpoints']} endpoints extracted")
            except Exception:
                pass
        
        # PHASE 6.3: Advanced API Detection
        if all_js_files:
            try:
                console.print(f"\n[bold cyan]Phase 6.3:[/bold cyan] API Detection")
                from .api_detector import APIDetector
                
                api_detector = APIDetector()
                all_api_endpoints = []
                
                # Detect APIs in all JS files
                for js_file in all_js_files:
                    content = js_file.get('content', '')
                    url = js_file.get('url', '')
                    if content:
                        api_endpoints = api_detector.detect_api_endpoints(content, url)
                        all_api_endpoints.extend(api_endpoints)
                
                # Detect API keys in URLs
                all_urls = list(all_urls_to_crawl)
                api_key_findings = api_detector.detect_api_keys_in_urls(all_urls)
                
                # Analyze API structure
                api_analysis = api_detector.analyze_api_structure(all_api_endpoints)
                
                # Store results
                self.results['api_endpoints'] = all_api_endpoints
                self.results['api_key_findings'] = api_key_findings
                self.results['api_analysis'] = api_analysis
                
                console.print(f"  [green][+][/green] {len(all_api_endpoints)} API endpoints detected")
                if api_key_findings:
                    console.print(f"  [yellow][!][/yellow] {len(api_key_findings)} API keys found in URLs")
                
                # Show API breakdown
                if api_analysis['by_classification']:
                    console.print(f"  [cyan]API Types:[/cyan]")
                    for api_type, count in sorted(api_analysis['by_classification'].items(), key=lambda x: x[1], reverse=True)[:5]:
                        console.print(f"    [+] {api_type}: {count}")
                
            except Exception as e:
                console.print(f"  [yellow][!][/yellow] API detection failed")
        
        # PHASE 6.4: Swagger/OpenAPI Detection
        try:
            console.print(f"\n[bold cyan]Phase 6.4:[/bold cyan] Swagger/OpenAPI Detection")
            from .swagger_detector import SwaggerDetector
            
            async with SwaggerDetector(timeout=10, max_concurrent=20) as swagger_detector:
                swagger_result = await swagger_detector.discover_and_extract(target_url)
                
                if swagger_result.get('success'):
                    specs_found = swagger_result.get('specs_found', 0)
                    total_endpoints = swagger_result.get('total_endpoints', 0)
                    
                    # Store results
                    self.results['swagger_specs'] = swagger_result.get('spec_details', [])
                    self.results['swagger_endpoints'] = swagger_result.get('endpoints', [])
                    
                    # Add to API endpoints
                    for endpoint in swagger_result.get('endpoints', []):
                        api_endpoint = {
                            'endpoint': endpoint['full_path'],
                            'method': endpoint['method'],
                            'classification': 'Swagger API',
                            'parameters': [p['name'] for p in endpoint.get('parameters', [])],
                            'source': 'swagger',
                            'tags': endpoint.get('tags', []),
                            'deprecated': endpoint.get('deprecated', False),
                        }
                        self.results.setdefault('api_endpoints', []).append(api_endpoint)
                    
                    console.print(f"  [green][+][/green] {specs_found} Swagger specs found")
                    console.print(f"  [green][+][/green] {total_endpoints} API endpoints extracted")
                    
                    # Show spec details
                    if swagger_result.get('spec_details'):
                        console.print(f"  [cyan]Discovered Specs:[/cyan]")
                        for spec in swagger_result['spec_details'][:5]:  # Show first 5
                            version = spec.get('version', 'unknown')
                            endpoint_count = spec.get('endpoint_count', 0)
                            console.print(f"    [+] {spec['path']} (v{version}): {endpoint_count} endpoints")
                else:
                    console.print(f"  [yellow][!][/yellow] No Swagger specs found")
        except Exception as e:
            console.print(f"  [yellow][!][/yellow] Swagger detection failed: {str(e)[:50]}")
        
        # PHASE 6.5: Source Map Detection and Fetching
        if all_js_files:
            try:
                console.print(f"\n[bold cyan]Phase 6.5:[/bold cyan] Source Map Discovery")
                from .sourcemap_detector import SourceMapDetector
                
                sourcemap_detector = SourceMapDetector(timeout=10)
                sourcemap_result = await sourcemap_detector.discover_and_fetch_sourcemaps(all_js_files)
                
                sourcemaps = sourcemap_result.get('sourcemaps', [])
                if sourcemaps:
                    # Add source maps as additional JS files for analysis
                    for smap in sourcemaps:
                        map_file = {
                            'url': smap['url'],
                            'content': smap['content'],
                            'size': smap['size'],
                            'hash': calculate_sha256(smap['content']),
                            'source': 'sourcemap',
                            'type': 'sourcemap',
                            'source_js': smap.get('source_js', '')
                        }
                        all_js_files.append(map_file)
                    
                    console.print(f"  [green][+][/green] {len(sourcemaps)} source maps fetched")
                else:
                    console.print(f"  [yellow][!][/yellow] No source maps found")
            except Exception as e:
                console.print(f"  [yellow][!][/yellow] Source map detection failed")
        
        # PHASE 7: Secret Detection
        if all_js_files:
            try:
                console.print(f"\n[bold cyan]Phase 7:[/bold cyan] Secret Detection")
                from .mantra_secrets import MantraSecretScanner
                
                mantra_scanner = MantraSecretScanner(timeout=120)
                if mantra_scanner.is_available():
                    mantra_result = await mantra_scanner.scan_multiple_files(all_js_files)
                    
                    if mantra_result.get('success'):
                        # Store Mantra secrets for later integration
                        self.results['mantra_secrets'] = mantra_result.get('secrets', [])
                        console.print(f"  [green][+][/green] {mantra_result['total_secrets']} secrets found")
                    else:
                        console.print(f"  [yellow][!][/yellow] Mantra scan failed")
                else:
                    console.print(f"  [yellow][!][/yellow] Mantra not available")
            except Exception:
                pass
        
        # PHASE 7.5: Version Detection
        if all_js_files:
            try:
                console.print(f"\n[bold cyan]Phase 7.5:[/bold cyan] Version Detection")
                from .version_detector import VersionDetector
                
                version_detector = VersionDetector()
                all_versions = []
                
                # Detect versions in all JS files
                for js_file in all_js_files:
                    content = js_file.get('content', '')
                    url = js_file.get('url', '')
                    if content:
                        versions = version_detector.detect_versions(content, url)
                        all_versions.extend(versions)
                
                # Analyze versions
                version_analysis = version_detector.analyze_versions(all_versions)
                
                # Store results
                self.results['detected_versions'] = all_versions
                self.results['version_analysis'] = version_analysis
                
                console.print(f"  [green][+][/green] {version_analysis['total_libraries']} libraries detected")
                
                # Show top libraries (filter out false positives)
                if version_analysis['by_library']:
                    valid_libs = []
                    for lib in version_analysis['unique_libraries']:
                        # Skip obvious false positives
                        if len(lib) > 2 and not lib.isdigit():
                            versions = version_analysis['by_library'].get(lib, [])
                            valid_libs.append((lib, versions))
                    
                    if valid_libs:
                        console.print(f"  [cyan]Detected Libraries:[/cyan]")
                        for lib, versions in sorted(valid_libs)[:15]:  # Show top 15
                            unique_versions = list(set(versions))[:3]  # Max 3 versions
                            console.print(f"    [+] {lib}: {', '.join(unique_versions)}")
                    else:
                        console.print(f"  [yellow][!][/yellow] No valid libraries detected")
                
            except Exception:
                console.print(f"  [yellow][!][/yellow] Version detection failed")
        
        # PHASE 7.7: CVE Lookup
        if self.results.get('detected_versions'):
            try:
                console.print(f"\n[bold cyan]Phase 7.7:[/bold cyan] CVE Lookup")
                from .cve_lookup import CVELookup
                
                cve_lookup = CVELookup(timeout=30)
                
                # Get unique library versions
                unique_libs = []
                seen = set()
                for ver in self.results['detected_versions']:
                    key = f"{ver['library']}:{ver['version']}"
                    if key not in seen:
                        seen.add(key)
                        unique_libs.append(ver)
                
                console.print(f"  [cyan]Checking {len(unique_libs)} libraries for CVEs...[/cyan]")
                
                # Batch lookup CVEs
                cve_results = await cve_lookup.batch_lookup(unique_libs)
                
                # Store results
                self.results['cve_results'] = cve_results
                
                if cve_results['total_cves'] > 0:
                    console.print(f"  [red]![/red] {cve_results['total_cves']} CVEs found")
                    console.print(f"    [+] Critical: {cve_results['critical']}")
                    console.print(f"    [+] High: {cve_results['high']}")
                    console.print(f"    [+] Medium: {cve_results['medium']}")
                    console.print(f"    [+] Low: {cve_results['low']}")
                else:
                    console.print(f"  [green][+][/green] No CVEs found")
                
            except Exception as e:
                console.print(f"  [yellow][!][/yellow] CVE lookup failed")
        
        # Deduplicate by hash
        unique_js_files = deduplicate_by_hash(all_js_files, 'hash')
        
        console.print(f"\n[bold green][+] Collection Complete:[/bold green] {len(unique_js_files)} unique JS files")
        
        return unique_js_files
        
        # Wayback Machine collection
        if self.enable_wayback:
            try:
                async with WaybackIntegration(timeout=30, max_concurrent=5) as wayback:
                    domain = extract_domain(target)
                    wayback_files = await wayback.discover_historical_js(domain, limit=500)
                    
                    if wayback_files:
                        for wb_file in wayback_files:
                            if wb_file.get('content'):
                                js_file = {
                                    'url': wb_file['url'],
                                    'content': wb_file['content'],
                                    'size': wb_file['size'],
                                    'hash': calculate_sha256(wb_file['content']),
                                    'source': 'wayback',
                                    'type': 'historical'
                                }
                                all_js_files.append(js_file)
                        console.print(f"[green]  + Found {len(wayback_files)} files from Wayback[/green]")
                    
            except Exception as e:
                error_msg = f"Wayback collection failed: {str(e)}"
                self.results['errors'].append(error_msg)
        
        # GAU collection
        if self.enable_gau:
            try:
                gau = GAUIntegration(timeout=60)
                if gau.is_available():
                    domain = extract_domain(target)
                    gau_js_urls = await gau.discover_js_urls(domain)
                    
                    if gau_js_urls:
                        # Limit to 50 URLs to avoid overwhelming
                        limited_urls = gau_js_urls[:50]
                        console.print(f"[cyan]  + Fetching {len(limited_urls)} URLs from GAU...[/cyan]")
                        
                        # Fetch content for GAU URLs with timeout
                        async with JSCollector(timeout=5, max_concurrent=10) as collector:
                            for gau_url in limited_urls:
                                try:
                                    js_result = await asyncio.wait_for(
                                        collector.collect_from_url(gau_url['url']),
                                        timeout=5
                                    )
                                    if js_result.get('js_files'):
                                        for js_file in js_result['js_files']:
                                            js_file['source'] = 'gau'
                                            all_js_files.append(js_file)
                                except (asyncio.TimeoutError, Exception):
                                    # Skip individual URL failures
                                    continue
                        console.print(f"[green]  + Collected {len([f for f in all_js_files if f.get('source') == 'gau'])} files from GAU[/green]")
                else:
                    self.results['errors'].append("GAU tool not available")
                    
            except Exception as e:
                error_msg = f"GAU collection failed: {str(e)}"
                self.results['errors'].append(error_msg)
        
        # Deduplicate by hash
        unique_js_files = deduplicate_by_hash(all_js_files, 'hash')
        
        return unique_js_files
    
    async def _setup_plugins(self) -> None:
        """Load and configure plugins."""
        # Load plugins
        await self.plugin_manager.load_plugins()
        
        # Configure plugins based on CLI arguments
        disabled_plugins = self.config.get('disabled_plugins', [])
        enabled_plugins = self.config.get('enabled_plugins', [])
        
        for plugin_name in disabled_plugins:
            self.plugin_manager.disable_plugin(plugin_name)
        
        for plugin_name in enabled_plugins:
            self.plugin_manager.enable_plugin(plugin_name)
        
        # Enable profiling if requested
        if self.enable_profiling:
            self.plugin_manager.enable_profiling()
        
        logger.info("Plugins configured", 
                   total=len(self.plugin_manager.plugins),
                   enabled=len([p for p in self.plugin_manager.plugins.values() if p.is_enabled()]))
    
    async def _execute_plugins(self, target: str, js_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute all enabled plugins."""
        # Create plugin context
        context = PluginContext(
            target=target,
            js_files=js_files,
            config=self.config,
            profiling_enabled=self.enable_profiling
        )
        
        # Execute plugins
        plugin_results = await self.plugin_manager.execute_plugins(context)
        
        # Record profiling data for each plugin
        if self.enable_profiling:
            for plugin_name, result in plugin_results.items():
                plugin = self.plugin_manager.get_plugin_by_name(plugin_name)
                if plugin:
                    self.profiling_engine.profile_plugin_execution(
                        plugin_name=plugin_name,
                        category=plugin.metadata.category.value,
                        execution_time=result.execution_time,
                        memory_usage=result.memory_usage,
                        network_calls=result.network_calls,
                        findings_count=len(result.findings),
                        errors_count=len(result.errors),
                        success=len(result.errors) == 0,
                        metadata=result.metadata
                    )
        
        return plugin_results
    
    def _consolidate_plugin_results(self, plugin_results: Dict[str, Any]) -> None:
        """Consolidate results from all plugins."""
        all_findings = []
        consolidated_secrets = []
        consolidated_endpoints = []
        consolidated_vulnerabilities = []
        
        # Process each plugin's results
        for plugin_name, result in plugin_results.items():
            # Collect all findings
            for finding in result.findings:
                finding['plugin_source'] = plugin_name
                all_findings.append(finding)
            
            # Consolidate by type
            if plugin_name == 'secret_detection':
                # Extract secrets from shared context or findings
                secrets = [f for f in result.findings if f.get('type') == 'secret']
                consolidated_secrets.extend(secrets)
            
            elif plugin_name == 'api_intelligence':
                # Extract API vulnerabilities
                api_vulns = [f for f in result.findings if f.get('type') == 'api_vulnerability']
                consolidated_vulnerabilities.extend(api_vulns)
                
                # Extract endpoints from metadata or shared context
                endpoints = result.metadata.get('endpoints_analyzed', [])
                consolidated_endpoints.extend(endpoints)
            
            elif plugin_name == 'cve_intelligence':
                # Extract library vulnerabilities
                cve_vulns = [f for f in result.findings if f.get('type') == 'vulnerable_library']
                consolidated_vulnerabilities.extend(cve_vulns)
            
            elif plugin_name == 'dom_flow_analysis':
                # Extract DOM XSS vulnerabilities
                dom_vulns = [f for f in result.findings if f.get('type') == 'dom_xss']
                consolidated_vulnerabilities.extend(dom_vulns)
        
        # Integrate Mantra secrets
        mantra_secrets = self.results.get('mantra_secrets', [])
        if mantra_secrets:
            # Convert Mantra format to standard secret format
            for mantra_secret in mantra_secrets:
                secret = {
                    'type': 'secret',
                    'secret_type': mantra_secret.get('type', 'unknown'),
                    'description': f"Secret detected by Mantra: {mantra_secret.get('type', 'unknown')}",
                    'value': mantra_secret.get('value', ''),
                    'severity': self._map_mantra_confidence_to_severity(mantra_secret.get('confidence', 'medium')),
                    'confidence': self._map_mantra_confidence_to_score(mantra_secret.get('confidence', 'medium')),
                    'source_file': mantra_secret.get('source_url', ''),
                    'line': mantra_secret.get('line', 0),
                    'tool': 'mantra',
                    'plugin_source': 'mantra_integration'
                }
                consolidated_secrets.append(secret)
                all_findings.append(secret)
        
        # Store consolidated results
        self.results['all_findings'] = all_findings
        self.results['secrets'] = consolidated_secrets
        self.results['endpoints'] = consolidated_endpoints
        self.results['vulnerabilities'] = consolidated_vulnerabilities
        
        # Sort findings by risk score
        self.results['all_findings'].sort(key=lambda x: x.get('risk_score', 0), reverse=True)
    
    def _map_mantra_confidence_to_severity(self, confidence: str) -> str:
        """Map Mantra confidence levels to severity."""
        mapping = {
            'high': 'high',
            'medium': 'medium',
            'low': 'low'
        }
        return mapping.get(confidence.lower(), 'medium')
    
    def _map_mantra_confidence_to_score(self, confidence: str) -> float:
        """Map Mantra confidence levels to numeric scores."""
        mapping = {
            'high': 0.9,
            'medium': 0.7,
            'low': 0.5
        }
        return mapping.get(confidence.lower(), 0.7)
    
    def _generate_statistics(self) -> None:
        """Generate comprehensive scan statistics."""
        stats = {
            'total_js_files': len(self.results['js_files']),
            'total_findings': len(self.results['all_findings']),
            'total_secrets': len(self.results.get('secrets', [])),
            'total_endpoints': len(self.results.get('endpoints', [])),
            'total_parameters': len(self.results.get('parameters', [])),
            'total_vulnerabilities': len(self.results.get('vulnerabilities', [])),
            'total_errors': len(self.results['errors']),
            'file_sources': {},
            'finding_types': {},
            'risk_distribution': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
            'plugin_statistics': {},
            'parameter_types': {},
            'endpoint_priorities': {'high': 0, 'medium': 0, 'low': 0}
        }
        
        # File source distribution
        for js_file in self.results['js_files']:
            source = js_file.get('source', 'unknown')
            stats['file_sources'][source] = stats['file_sources'].get(source, 0) + 1
        
        # Finding type distribution
        for finding in self.results['all_findings']:
            finding_type = finding.get('type', 'unknown')
            stats['finding_types'][finding_type] = stats['finding_types'].get(finding_type, 0) + 1
            
            # Risk distribution
            severity = finding.get('severity', 'low')
            risk_level = severity.title()  # Convert to title case
            if risk_level in stats['risk_distribution']:
                stats['risk_distribution'][risk_level] += 1
        
        # Parameter type distribution
        from dataclasses import is_dataclass, asdict
        for param in self.results.get('parameters', []):
            # Handle dataclass objects
            if is_dataclass(param):
                param_dict = asdict(param)
                param_type = param_dict.get('param_type', 'unknown')
            else:
                param_type = param.get('param_type', param.get('type', 'unknown'))
            stats['parameter_types'][param_type] = stats['parameter_types'].get(param_type, 0) + 1
        
        # Endpoint priority distribution
        for endpoint in self.results.get('endpoints', []):
            priority = endpoint.get('priority', 'low')
            if priority in stats['endpoint_priorities']:
                stats['endpoint_priorities'][priority] += 1
        
        # Plugin statistics
        for plugin_name, result in self.results.get('plugin_results', {}).items():
            stats['plugin_statistics'][plugin_name] = {
                'findings_count': len(result.findings),
                'errors_count': len(result.errors),
                'execution_time': result.execution_time,
                'memory_usage': result.memory_usage,
                'network_calls': result.network_calls,
                'success': len(result.errors) == 0
            }
        
        # Calculate total file size
        total_size = sum(js_file.get('size', 0) for js_file in self.results['js_files'])
        stats['total_js_size'] = total_size
        stats['average_file_size'] = total_size // stats['total_js_files'] if stats['total_js_files'] > 0 else 0
        
        self.results['statistics'] = stats
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of scan results."""
        stats = self.results.get('statistics', {})
        
        return {
            'target': self.results['target'],
            'scan_status': 'completed' if not self.results['errors'] else 'completed_with_errors',
            'total_js_files': stats.get('total_js_files', 0),
            'total_findings': stats.get('total_findings', 0),
            'total_secrets': stats.get('total_secrets', 0),
            'critical_findings': stats.get('risk_distribution', {}).get('Critical', 0),
            'high_findings': stats.get('risk_distribution', {}).get('High', 0),
            'total_endpoints': stats.get('total_endpoints', 0),
            'total_vulnerabilities': stats.get('total_vulnerabilities', 0),
            'plugins_executed': len(self.results.get('plugin_results', {})),
            'successful_plugins': len([r for r in self.results.get('plugin_results', {}).values() if len(r.errors) == 0]),
            'errors': len(self.results.get('errors', [])),
            'file_size_mb': round(stats.get('total_js_size', 0) / (1024 * 1024), 2),
            'scan_duration': self.results.get('scan_metadata', {}).get('duration', 0),
            'profiling_enabled': self.enable_profiling,
            'graph_generated': self.enable_graph and bool(self.results.get('attack_surface_graph'))
        }