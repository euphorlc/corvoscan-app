import re
import json
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional
from abc import ABC, abstractmethod

@dataclass
class ParsedResult:
    """Base class for parsed results from any tool"""
    tool_name: str
    target: str
    timestamp: str
    raw_output: str
    success: bool
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON export"""
        return asdict(self)

class ToolResultsParser(ABC):
    """Abstract base class for tool-specific result parsers"""
    
    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.raw_lines = []
        
    def add_output_line(self, line: str):
        """Add a line of output from the tool"""
        self.raw_lines.append(line.rstrip())
    
    def get_raw_output(self) -> str:
        """Get the complete raw output"""
        return "\n".join(self.raw_lines)
    
    @abstractmethod
    def parse(self, target: str) -> ParsedResult:
        """Parse the collected output and return structured results"""
        pass
    
    def clear(self):
        """Clear accumulated output"""
        self.raw_lines.clear()

class ResultsManager:
    """Central manager for handling results from all tools"""
    
    def __init__(self):
        self.parsers: Dict[str, ToolResultsParser] = {}
        self.results: List[ParsedResult] = []
        
    def register_parser(self, tool_name: str, parser: ToolResultsParser):
        """Register a parser for a specific tool"""
        self.parsers[tool_name] = parser
    
    def get_parser(self, tool_name: str):
        """Get a registered parser by tool name"""
        return self.parsers.get(tool_name)
        
    def add_output_line(self, tool_name: str, line: str):
        """Add output line to the appropriate parser"""
        if tool_name in self.parsers:
            self.parsers[tool_name].add_output_line(line)
    
    def parse_results(self, tool_name: str, target: str) -> Optional[ParsedResult]:
        """Parse results for a specific tool"""
        if tool_name in self.parsers:
            try:
                result = self.parsers[tool_name].parse(target)
                self.results.append(result)
                return result
            except Exception as e:
                # Create error result
                error_result = ParsedResult(
                    tool_name=tool_name,
                    target=target,
                    timestamp=datetime.now().isoformat(),
                    raw_output=self.parsers[tool_name].get_raw_output(),
                    success=False,
                    error_message=f"Parsing error: {str(e)}"
                )
                self.results.append(error_result)
                return error_result
        return None
    
    def get_all_results(self) -> List[ParsedResult]:
        """Get all parsed results"""
        return self.results
    
    def get_results_by_tool(self, tool_name: str) -> List[ParsedResult]:
        """Get results for a specific tool"""
        return [r for r in self.results if r.tool_name == tool_name]
    
    def clear_results(self):
        """Clear all results and parser states"""
        self.results.clear()
        for parser in self.parsers.values():
            parser.clear()
    
    def export_to_json(self, filename: str = None) -> str:
        """Export all results to JSON format"""
        if filename is None:
            filename = f"corvoscan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        export_data = {
            "export_info": {
                "tool": "CorvoScan",
                "version": "1.0",
                "timestamp": datetime.now().isoformat(),
                "total_results": len(self.results)
            },
            "results": [result.to_dict() for result in self.results]
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        return filename
    
    def export_to_csv(self, filename: str = None) -> str:
        """Export results to CSV format"""
        import csv
        
        if filename is None:
            filename = f"corvoscan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        if not self.results:
            return filename
        
        # Get all possible field names from all results
        fieldnames = set()
        for result in self.results:
            fieldnames.update(result.to_dict().keys())
        
        fieldnames = sorted(list(fieldnames))
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for result in self.results:
                writer.writerow(result.to_dict())
        
        return filename