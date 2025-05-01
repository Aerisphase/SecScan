import abc
import importlib
import os
import pkgutil
import inspect
import abc
from typing import Dict, List, Type, Optional, Any

class BaseScannerPlugin(abc.ABC):
    """
    Abstract base class for all vulnerability scanner plugins.
    
    Attributes:
        name (str): Unique name of the scanner plugin
        description (str): Brief description of the scanner's purpose
        severity_levels (List[str]): Supported severity levels
    """
    name: str = "base_scanner"
    description: str = "Base vulnerability scanner plugin"
    severity_levels: List[str] = ["low", "medium", "high", "critical"]
    
    @abc.abstractmethod
    async def scan(self, page: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan a single page for vulnerabilities.
        
        Args:
            page (Dict): Page data from crawler
        
        Returns:
            List of vulnerability dictionaries
        """
        pass
    
    def validate_vulnerability(self, vulnerability: Dict[str, Any]) -> bool:
        """
        Validate the structure of a vulnerability report.
        
        Args:
            vulnerability (Dict): Vulnerability dictionary to validate
        
        Returns:
            bool: Whether the vulnerability is valid
        """
        required_keys = [
            "type", 
            "severity", 
            "description", 
            "location"
        ]
        
        return all(key in vulnerability for key in required_keys) and \
               vulnerability.get("severity") in self.severity_levels

class ScannerRegistry:
    """
    Manages scanner plugins with dynamic discovery and registration.
    """
    _instance = None
    _scanners: Dict[str, Type[BaseScannerPlugin]] = {}
    
    def __new__(cls):
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    def discover_scanners(cls):
        """Automatically discover and register scanner plugins."""
        # Clear existing scanners to prevent duplicate registrations
        cls._scanners.clear()
        
        try:
            # Get the directory of the current module
            current_dir = os.path.dirname(os.path.abspath(__file__))
            scanners_dir = os.path.join(current_dir, 'scanners')
            
            # Print debug information about scanner discovery
            print(f"Scanner discovery started. Scanning directory: {scanners_dir}")
            print(f"Files in directory: {os.listdir(scanners_dir)}")
            
            # Dynamically import scanner modules
            for filename in os.listdir(scanners_dir):
                if filename.endswith('.py') and not filename.startswith('__'):
                    name = filename[:-3]  # Remove .py extension
                    try:
                        module_name = f'src.core.scanners.{name}'
                        print(f"Attempting to import module: {module_name}")
                        module = importlib.import_module(module_name)
                        
                        # Find and register scanner classes
                        registered_count = 0
                        for member_name, obj in inspect.getmembers(module):
                            if inspect.isclass(obj):
                                print(f"Examining class member: {member_name}, type: {type(obj)}, module: {obj.__module__ if hasattr(obj, '__module__') else 'N/A'}, bases: {obj.__bases__}")
                                try:
                                    # Check if the class inherits from BaseScannerPlugin
                                    if any(base is BaseScannerPlugin for base in obj.__bases__):
                                        print(f"Potential scanner class found: {member_name}")
                                        print(f"Bases: {obj.__bases__}, Type: {type(obj)}")
                                        print(f"Attributes: {dir(obj)}")
                                        # Check if the required attributes are present
                                        if not hasattr(obj, 'name'):
                                            print(f"WARNING: {member_name} lacks 'name' attribute")
                                except TypeError as e:
                                    print(f"Error checking subclass for {member_name}: {e}")
                            if (
                                inspect.isclass(obj) and 
                                (obj.__module__ == module.__name__ or 
                                 obj.__module__.startswith('src.core.scanners.')) and
                                (BaseScannerPlugin in obj.__bases__ or 
                                 any(base.__name__ == 'BaseScannerPlugin' for base in obj.__bases__)) and 
                                obj is not BaseScannerPlugin
                            ):
                                print(f"Full details for {member_name}:")
                                print(f"  Module: {obj.__module__}")
                                print(f"  Bases: {obj.__bases__}")
                                print(f"  Attributes: {dir(obj)}")
                                print(f"  Inheritance path: {inspect.getmro(obj)}")
                                try:
                                    cls.register_scanner(obj)
                                    registered_count += 1
                                    print(f"Registered scanner: {obj.__name__}")
                                except Exception as reg_err:
                                    print(f"Failed to register scanner {obj.__name__}: {reg_err}")
                        
                        if registered_count == 0:
                            print(f"No scanners found in module {module_name}")
                    except ImportError as e:
                        print(f"Could not import scanner module {name}: {e}")
            
            # Print total registered scanners
            print(f"Total scanners registered: {len(cls._scanners)}")
            print(f"Registered scanner names: {list(cls._scanners.keys())}")
        except Exception as e:
            print(f"Error discovering scanners: {e}")
    
    @classmethod
    def register_scanner(cls, scanner_class: Type[BaseScannerPlugin]):
        """Register a scanner plugin.
        
        Args:
            scanner_class (Type[BaseScannerPlugin]): Scanner class to register
        """
        print(f"Attempting to register scanner class: {scanner_class.__name__}")
        print(f"  Module: {scanner_class.__module__}")
        print(f"  Bases: {scanner_class.__bases__}")
        print(f"  Attributes: {dir(scanner_class)}")
        print(f"  Inheritance path: {inspect.getmro(scanner_class)}")
        
        # Validate scanner class
        if not issubclass(scanner_class, BaseScannerPlugin):
            print(f"Error: {scanner_class.__name__} is not a subclass of BaseScannerPlugin")
            raise ValueError(f"Scanner class {scanner_class.__name__} must inherit from BaseScannerPlugin")
        
        if not hasattr(scanner_class, 'name'):
            print(f"Error: Scanner class {scanner_class.__name__} lacks 'name' attribute")
            raise ValueError(f"Scanner class {scanner_class.__name__} must have a 'name' attribute")
        
        if not hasattr(scanner_class, 'scan'):
            print(f"Error: Scanner class {scanner_class.__name__} lacks 'scan' method")
            raise ValueError(f"Scanner class {scanner_class.__name__} must have an async scan method")
        
        print(f"Registering scanner with name: {scanner_class.name}")
        cls._scanners[scanner_class.name] = scanner_class
    
    @classmethod
    def get_all_scanners(cls) -> List[Type[BaseScannerPlugin]]:
        """
        Get all registered scanner classes.
        
        Returns:
            List of scanner classes
        """
        return list(cls._scanners.values())
    
    @classmethod
    def get_scanner(cls, name: Optional[str] = None) -> List[BaseScannerPlugin]:
        """Get registered scanners.
        
        Args:
            name (Optional[str]): Name of a specific scanner to retrieve.
        
        Returns:
            List of scanner instances
        """
        if name:
            scanner_class = cls._scanners.get(name)
            if not scanner_class:
                # Return an empty list instead of raising an error
                return []
            return [scanner_class()]
        
        return [scanner_class() for scanner_class in cls._scanners.values()]
    
    @classmethod
    def list_scanners(cls) -> List[str]:
        """List names of all registered scanners.
        
        Returns:
            List of scanner names
        """
        return list(cls._scanners.keys())

# Initialize scanner discovery on import
ScannerRegistry.discover_scanners()
