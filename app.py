from flask import Flask, request, render_template, send_file, redirect, session, jsonify
import gzip
import io
import base64
import json
import struct
import zlib
import re
import math

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

def parse_binary_structures(data_bytes):
    """Parse binary data structures commonly found in game save files"""
    structures = {
        'strings': [],
        'floats': [],
        'integers': [],
        'possible_items': [],
        'coordinates': [],
        'binary_analysis': {}
    }
    
    try:
        # Extract null-terminated strings (common in game saves)
        null_terminated_strings = []
        current_string = b""
        for byte in data_bytes:
            if byte == 0:  # Null terminator
                if len(current_string) > 3:  # Minimum length for meaningful strings
                    try:
                        decoded = current_string.decode('utf-8', errors='ignore')
                        if decoded.strip() and all(ord(c) < 127 for c in decoded):  # ASCII only
                            null_terminated_strings.append(decoded.strip())
                    except:
                        pass
                current_string = b""
            elif 32 <= byte <= 126:  # Printable ASCII
                current_string += bytes([byte])
            else:
                if len(current_string) > 3:
                    try:
                        decoded = current_string.decode('utf-8', errors='ignore')
                        if decoded.strip() and all(ord(c) < 127 for c in decoded):
                            null_terminated_strings.append(decoded.strip())
                    except:
                        pass
                current_string = b""
        
        structures['strings'] = list(set(null_terminated_strings))  # Remove duplicates
        
        # Parse 32-bit floats (little-endian and big-endian)
        floats = []
        for i in range(0, len(data_bytes) - 3, 1):
            try:
                # Little-endian float
                value_le = struct.unpack('<f', data_bytes[i:i+4])[0]
                if -1000000 < value_le < 1000000 and not (value_le == 0.0):  # Reasonable range
                    floats.append(('LE', i, value_le))
                
                # Big-endian float
                value_be = struct.unpack('>f', data_bytes[i:i+4])[0]
                if -1000000 < value_be < 1000000 and not (value_be == 0.0):
                    floats.append(('BE', i, value_be))
            except:
                continue
        
        structures['floats'] = floats[:100]  # Limit output
        
        # Parse 32-bit integers
        integers = []
        for i in range(0, len(data_bytes) - 3, 4):  # Step by 4 for proper alignment
            try:
                # Little-endian int
                value_le = struct.unpack('<I', data_bytes[i:i+4])[0]
                if 1 <= value_le <= 100000:  # Reasonable range for game data
                    integers.append(('LE', i, value_le))
                
                # Big-endian int
                value_be = struct.unpack('>I', data_bytes[i:i+4])[0]
                if 1 <= value_be <= 100000:
                    integers.append(('BE', i, value_be))
            except:
                continue
        
        structures['integers'] = integers[:50]  # Limit output
        
        # Look for Unity serialization markers
        unity_markers = [
            b'GameObject',
            b'Transform',
            b'MonoBehaviour',
            b'Prefab',
            b'PlayerData',
            b'SaveData',
            b'Inventory',
            b'Player'
        ]
        
        unity_found = []
        for marker in unity_markers:
            if marker in data_bytes:
                pos = data_bytes.find(marker)
                unity_found.append(f"{marker.decode()} at position {pos}")
        
        structures['binary_analysis']['unity_markers'] = unity_found
        
        # Look for coordinate patterns (3 consecutive floats)
        potential_coords = []
        i = 0
        while i < len(data_bytes) - 11:  # 3 floats = 12 bytes
            try:
                x = struct.unpack('<f', data_bytes[i:i+4])[0]
                y = struct.unpack('<f', data_bytes[i+4:i+8])[0]
                z = struct.unpack('<f', data_bytes[i+8:i+12])[0]
                
                # Check if these look like reasonable coordinates
                if (-10000 < x < 10000 and -10000 < y < 10000 and -10000 < z < 10000 and
                    not (x == 0 and y == 0 and z == 0)):
                    potential_coords.append({
                        'offset': i,
                        'x': x,
                        'y': y,
                        'z': z
                    })
            except:
                pass
            i += 4
        
        structures['coordinates'] = potential_coords[:20]  # Limit output
        
        return structures
        
    except Exception as e:
        return {'error': f"Binary parsing failed: {str(e)}"}

def extract_unity_strings(data_bytes):
    """Extract strings using Unity-style string table format"""
    strings = []
    
    try:
        # Look for Unity string table patterns
        # Unity often stores strings with length prefix
        i = 0
        while i < len(data_bytes) - 4:
            try:
                # Try reading a 32-bit length (little-endian)
                str_len = struct.unpack('<I', data_bytes[i:i+4])[0]
                
                # Reasonable string length (1-1000 characters)
                if 1 <= str_len <= 1000 and i + 4 + str_len <= len(data_bytes):
                    string_data = data_bytes[i+4:i+4+str_len]
                    try:
                        decoded = string_data.decode('utf-8', errors='ignore')
                        # Check if it looks like a meaningful string
                        if (decoded.strip() and 
                            len(decoded.strip()) > 2 and
                            any(c.isalpha() for c in decoded) and
                            not any(ord(c) > 127 for c in decoded)):
                            strings.append({
                                'offset': i,
                                'length': str_len,
                                'content': decoded.strip()
                            })
                    except:
                        pass
                    i += 4 + str_len
                else:
                    i += 1
            except:
                i += 1
        
        return strings[:100]  # Limit output
        
    except Exception as e:
        return []

def analyze_game_save_structure(data_bytes):
    """Advanced analysis of game save file structure"""
    analysis = {
        'file_type': 'unknown',
        'binary_structures': {},
        'unity_strings': [],
        'readable_content': {},
        'statistics': {}
    }
    
    try:
        # Basic statistics
        analysis['statistics'] = {
            'total_size': len(data_bytes),
            'null_bytes': data_bytes.count(0),
            'printable_ratio': sum(1 for b in data_bytes if 32 <= b <= 126) / len(data_bytes),
            'entropy': calculate_entropy(data_bytes)
        }
        
        # Check for known game save patterns
        if b'Unity' in data_bytes or b'GameObject' in data_bytes:
            analysis['file_type'] = 'Unity Save File'
        elif data_bytes.startswith(b'FLOW'):
            analysis['file_type'] = "Len's Island Character File"
        
        # Parse binary structures
        analysis['binary_structures'] = parse_binary_structures(data_bytes)
        
        # Extract Unity-style strings
        analysis['unity_strings'] = extract_unity_strings(data_bytes)
        
        # Try to find item/object names
        meaningful_strings = []
        all_strings = (analysis['binary_structures'].get('strings', []) + 
                      [s['content'] for s in analysis['unity_strings']])
        
        for string in all_strings:
            # Filter for likely item/object names
            if (len(string) > 2 and 
                not string.isdigit() and
                any(c.isalpha() for c in string) and
                string.lower() not in ['true', 'false', 'null', 'data', 'info', 'type']):
                meaningful_strings.append(string)
        
        analysis['readable_content']['meaningful_strings'] = list(set(meaningful_strings))[:50]
        
        return analysis
        
    except Exception as e:
        return {'error': f"Game save analysis failed: {str(e)}"}

def calculate_entropy(data_bytes):
    """Calculate the entropy of data to determine randomness/compression"""
    if not data_bytes:
        return 0
    
    # Count frequency of each byte value
    freq = {}
    for byte in data_bytes:
        freq[byte] = freq.get(byte, 0) + 1
    
    # Calculate entropy using proper logarithm
    entropy = 0
    data_len = len(data_bytes)
    for count in freq.values():
        p = count / data_len
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy

def format_game_save_analysis(analysis):
    """Format game save analysis into readable report"""
    if 'error' in analysis:
        return f"Error analyzing save file: {analysis['error']}"
    
    report = "=== ADVANCED GAME SAVE ANALYSIS ===\n\n"
    
    # File type and statistics
    report += f"🎮 FILE TYPE: {analysis.get('file_type', 'Unknown')}\n"
    stats = analysis.get('statistics', {})
    if stats:
        report += f"📊 SIZE: {stats.get('total_size', 0):,} bytes\n"
        report += f"📊 PRINTABLE RATIO: {stats.get('printable_ratio', 0)*100:.1f}%\n"
        report += f"📊 DATA ENTROPY: {stats.get('entropy', 0):.2f}\n\n"
    
    # Meaningful strings (likely item names, etc.)
    meaningful = analysis.get('readable_content', {}).get('meaningful_strings', [])
    if meaningful:
        report += "🏷️  POSSIBLE ITEM/OBJECT NAMES:\n"
        report += "=" * 50 + "\n"
        for item in sorted(meaningful):
            report += f"• {item}\n"
        report += f"\nTotal found: {len(meaningful)}\n\n"
    
    # Coordinates
    coords = analysis.get('binary_structures', {}).get('coordinates', [])
    if coords:
        report += "📍 COORDINATE DATA:\n"
        report += "=" * 50 + "\n"
        for i, coord in enumerate(coords[:5]):  # Show first 5
            report += f"Position {i+1}: X={coord['x']:.2f}, Y={coord['y']:.2f}, Z={coord['z']:.2f} (offset: {coord['offset']})\n"
        if len(coords) > 5:
            report += f"... and {len(coords) - 5} more coordinate sets\n"
        report += "\n"
    
    # Unity strings
    unity_strings = analysis.get('unity_strings', [])
    if unity_strings:
        report += "🔧 UNITY STRING DATA:\n"
        report += "=" * 50 + "\n"
        for string_info in unity_strings[:20]:  # Show first 20
            report += f"• {string_info['content']} (len: {string_info['length']})\n"
        if len(unity_strings) > 20:
            report += f"... and {len(unity_strings) - 20} more strings\n"
        report += "\n"
    
    # Binary structures summary
    binary = analysis.get('binary_structures', {})
    if binary.get('floats'):
        report += f"🔢 FOUND {len(binary['floats'])} FLOAT VALUES\n"
    if binary.get('integers'):
        report += f"🔢 FOUND {len(binary['integers'])} INTEGER VALUES\n"
    
    unity_markers = binary.get('binary_analysis', {}).get('unity_markers', [])
    if unity_markers:
        report += "\n🎯 UNITY MARKERS FOUND:\n"
        for marker in unity_markers:
            report += f"• {marker}\n"
    
    return report

def parse_lens_island_binary(data_bytes):
    """Parse Len's Island binary save data structures"""
    game_data = {
        'character_data': {},
        'inventory': [],
        'equipment': {},
        'progression': {},
        'location': {},
        'building_data': {},
        'farming_data': {},
        'raw_values': {},
        'technical_info': {}
    }
    
    try:
        # Look for character position data (usually stored as consecutive floats)
        coordinates = []
        i = 0
        while i < len(data_bytes) - 11:  # Need at least 12 bytes for 3 floats
            try:
                # Try reading 3 consecutive 32-bit floats (little-endian)
                x = struct.unpack('<f', data_bytes[i:i+4])[0]
                y = struct.unpack('<f', data_bytes[i+4:i+8])[0]
                z = struct.unpack('<f', data_bytes[i+8:i+12])[0]
                
                # Check if these look like reasonable game coordinates
                if (-10000 < x < 10000 and -10000 < y < 10000 and -10000 < z < 10000):
                    # Additional validation: check if values aren't just random
                    if not (abs(x) < 0.001 and abs(y) < 0.001 and abs(z) < 0.001):
                        coordinates.append({
                            'offset': i,
                            'x': x,
                            'y': y,
                            'z': z,
                            'type': 'position'
                        })
                        
                        # Check if next 3 floats might be rotation
                        if i + 23 < len(data_bytes):  # 12 + 12 - 1
                            try:
                                rx = struct.unpack('<f', data_bytes[i+12:i+16])[0]
                                ry = struct.unpack('<f', data_bytes[i+16:i+20])[0]
                                rz = struct.unpack('<f', data_bytes[i+20:i+24])[0]
                                
                                if (-360 <= rx <= 360 and -360 <= ry <= 360 and -360 <= rz <= 360):
                                    coordinates.append({
                                        'offset': i + 12,
                                        'x': rx,
                                        'y': ry,
                                        'z': rz,
                                        'type': 'rotation'
                                    })
                            except:
                                pass
                
                i += 4  # Move by 4 bytes each time
            except:
                i += 1
        
        # Set the most likely position data
        if coordinates:
            positions = [c for c in coordinates if c['type'] == 'position']
            rotations = [c for c in coordinates if c['type'] == 'rotation']
            
            if positions:
                best_pos = positions[0]  # Take the first reasonable position
                game_data['location']['coordinates'] = {
                    'x': best_pos['x'],
                    'y': best_pos['y'],
                    'z': best_pos['z']
                }
                game_data['technical_info']['position_offset'] = best_pos['offset']
            
            if rotations:
                best_rot = rotations[0]
                game_data['location']['rotation'] = {
                    'rx': best_rot['x'],
                    'ry': best_rot['y'],
                    'rz': best_rot['z']
                }
                game_data['technical_info']['rotation_offset'] = best_rot['offset']
        
        # Look for character stats (health, mana, etc.) as 32-bit floats/ints
        potential_stats = []
        for i in range(0, len(data_bytes) - 3, 4):
            try:
                # Try as float
                float_val = struct.unpack('<f', data_bytes[i:i+4])[0]
                if 0 < float_val <= 10000:  # Reasonable range for game stats
                    potential_stats.append(('float', i, float_val))
                
                # Try as integer
                int_val = struct.unpack('<I', data_bytes[i:i+4])[0]
                if 0 < int_val <= 100000:  # Reasonable range for game values
                    potential_stats.append(('int', i, int_val))
            except:
                continue
        
        # Common game stat ranges for classification
        health_range = (1, 1000)
        currency_range = (0, 1000000)
        level_range = (1, 100)
        
        # Try to identify stats by value ranges
        for stat_type, offset, value in potential_stats[:20]:  # Limit to first 20
            if health_range[0] <= value <= health_range[1]:
                if 'health' not in game_data['character_data']:
                    game_data['character_data']['health'] = value
            elif level_range[0] <= value <= level_range[1]:
                if 'level' not in game_data['character_data']:
                    game_data['character_data']['level'] = value
            elif currency_range[0] <= value <= currency_range[1]:
                if 'currency' not in game_data['character_data']:
                    game_data['character_data']['currency'] = value
        
        # Look for strings that might be item names or identifiers
        # Try to find length-prefixed strings (common in Unity)
        string_data = []
        i = 0
        while i < len(data_bytes) - 8:
            try:
                # Try reading a 32-bit length prefix
                str_len = struct.unpack('<I', data_bytes[i:i+4])[0]
                
                # Reasonable string length
                if 3 <= str_len <= 100 and i + 4 + str_len <= len(data_bytes):
                    string_bytes = data_bytes[i+4:i+4+str_len]
                    
                    # Try to decode as UTF-8
                    try:
                        decoded_str = string_bytes.decode('utf-8', errors='strict')
                        
                        # Check if it looks like a meaningful string
                        if (decoded_str.strip() and 
                            any(c.isalpha() for c in decoded_str) and
                            not any(ord(c) > 127 for c in decoded_str) and
                            len(decoded_str.strip()) >= 3):
                            
                            string_data.append({
                                'offset': i,
                                'length': str_len,
                                'content': decoded_str.strip()
                            })
                            
                            i += 4 + str_len  # Skip this string
                            continue
                    except UnicodeDecodeError:
                        pass
                
                i += 1
            except:
                i += 1
        
        # Filter strings to find likely item names
        meaningful_strings = []
        for string_info in string_data:
            content = string_info['content']
            
            # Skip obvious system strings
            if content.lower() in ['true', 'false', 'null', 'data', 'info', 'type', 'item', 'unity', 'gameobject']:
                continue
            
            # Skip strings that are all uppercase letters/numbers (likely IDs)
            if re.match(r'^[A-Z0-9_]+$', content):
                continue
            
            # Look for strings that might be item names
            if (len(content) >= 3 and 
                any(c.isalpha() for c in content) and
                not content.isdigit()):
                meaningful_strings.append(content)
        
        game_data['inventory'] = list(set(meaningful_strings))  # Remove duplicates
        game_data['technical_info']['total_strings_found'] = len(string_data)
        game_data['technical_info']['meaningful_strings'] = len(meaningful_strings)
        
        return game_data
        
    except Exception as e:
        return {'error': f"Binary parsing failed: {str(e)}"}

def parse_lens_island_data(text_content):
    """Parse Len's Island specific character data structures from text"""
    game_data = {
        'character_data': {},
        'inventory': [],
        'equipment': {},
        'progression': {},
        'location': {},
        'building_data': {},
        'farming_data': {},
        'raw_values': {}
    }
    
    try:
        # Extract coordinates (likely X, Y, Z positions)
        coords = re.findall(r'[-+]?\d+\.?\d+', text_content)
        if len(coords) >= 3:
            try:
                potential_coords = [float(c) for c in coords[:6]]  # First 6 numbers might be position/rotation
                game_data['location']['coordinates'] = {
                    'x': potential_coords[0] if len(potential_coords) > 0 else 0,
                    'y': potential_coords[1] if len(potential_coords) > 1 else 0,
                    'z': potential_coords[2] if len(potential_coords) > 2 else 0
                }
                if len(potential_coords) > 3:
                    game_data['location']['rotation'] = {
                        'rx': potential_coords[3],
                        'ry': potential_coords[4] if len(potential_coords) > 4 else 0,
                        'rz': potential_coords[5] if len(potential_coords) > 5 else 0
                    }
            except ValueError:
                pass
        
        # Look for proper English words that could be item names
        item_patterns = [
            r'\b(?:wood|stone|iron|gold|silver|copper|coal|food|meat|fish|seed|plant|tool|weapon|armor|potion|health|mana|sword|axe|hammer|bow|shield|helmet|chest|legs|boots|ring|amulet)\w*\b',
            r'\b[A-Z][a-z]+(?: [A-Z][a-z]+)*\b',  # Proper case words
            r'"([A-Za-z][A-Za-z\s]{3,30})"'  # Quoted strings
        ]
        
        for pattern in item_patterns:
            items = re.findall(pattern, text_content, re.IGNORECASE)
            for item in items:
                if (len(item) > 3 and 
                    item.lower() not in ['true', 'false', 'null', 'data', 'info', 'type', 'item', 'this', 'that', 'with', 'from'] and
                    not re.match(r'^[A-Z0-9_]{3,}$', item)):  # Skip encoded IDs
                    game_data['inventory'].append(item)
        
        # Look for character attributes with more specific patterns
        attribute_patterns = {
            'health': r'(?:health|hp|hitpoints)["\s]*[:\=]\s*(\d+\.?\d*)',
            'stamina': r'(?:stamina|energy|endurance)["\s]*[:\=]\s*(\d+\.?\d*)',
            'mana': r'(?:mana|mp|magic|magicka)["\s]*[:\=]\s*(\d+\.?\d*)',
            'level': r'(?:level|lvl|lv)["\s]*[:\=]\s*(\d+)',
            'experience': r'(?:exp|experience|xp)["\s]*[:\=]\s*(\d+)',
            'gold': r'(?:gold|money|coins|currency|cash)["\s]*[:\=]\s*(\d+)'
        }
        
        for attr_name, pattern in attribute_patterns.items():
            matches = re.findall(pattern, text_content, re.IGNORECASE)
            if matches:
                try:
                    game_data['character_data'][attr_name] = float(matches[0]) if '.' in matches[0] else int(matches[0])
                except ValueError:
                    game_data['character_data'][attr_name] = matches[0]
        
        # Look for character name 
        name_patterns = [
            r'(?:player|character)_?name["\s]*[:\=]\s*"([A-Za-z][A-Za-z\s]{2,20})"',
            r'"name"[:\s]*"([A-Za-z][A-Za-z\s]{2,20})"'
        ]
        
        for pattern in name_patterns:
            names = re.findall(pattern, text_content, re.IGNORECASE)
            for name in names:
                if (len(name) > 2 and 
                    name.lower() not in ['true', 'false', 'null', 'data', 'info', 'item', 'type'] and
                    not re.match(r'^[A-Z0-9_]+$', name)):
                    game_data['character_data']['name'] = name
                    break
        
        return game_data
        
    except Exception as e:
        return {'error': f"Failed to parse text data: {str(e)}", 'raw_data': text_content[:500]}

def format_lens_island_data(game_data):
    """Format parsed Len's Island data into a readable report"""
    if 'error' in game_data:
        return f"Error parsing game data: {game_data['error']}\n\nRaw data preview:\n{game_data.get('raw_data', '')}"
    
    report = "=== LEN'S ISLAND CHARACTER DATA ===\n\n"
    
    # Character Information
    if game_data['character_data']:
        report += "🧙 CHARACTER INFORMATION:\n"
        report += "=" * 40 + "\n"
        for key, value in game_data['character_data'].items():
            report += f"{key.upper()}: {value}\n"
        report += "\n"
    
    # Location Data
    if game_data['location']:
        report += "📍 LOCATION DATA:\n"
        report += "=" * 40 + "\n"
        if 'coordinates' in game_data['location']:
            coords = game_data['location']['coordinates']
            report += f"Position: X={coords.get('x', 0):.2f}, Y={coords.get('y', 0):.2f}, Z={coords.get('z', 0):.2f}\n"
        if 'rotation' in game_data['location']:
            rot = game_data['location']['rotation']
            report += f"Rotation: RX={rot.get('rx', 0):.2f}, RY={rot.get('ry', 0):.2f}, RZ={rot.get('rz', 0):.2f}\n"
        report += "\n"
    
    # Inventory (only meaningful items)
    if game_data['inventory']:
        meaningful_items = [item for item in game_data['inventory'] if not re.match(r'^[A-Z0-9_]{2,8}$', item)]
        if meaningful_items:
            report += "🎒 INVENTORY ITEMS:\n"
            report += "=" * 40 + "\n"
            unique_items = list(set(meaningful_items))
            for item in sorted(unique_items):
                report += f"• {item}\n"
            report += f"\nTotal meaningful items: {len(unique_items)}\n\n"
        else:
            report += "🎒 INVENTORY ITEMS:\n"
            report += "=" * 40 + "\n"
            report += "Note: Found encoded item data but no readable item names.\n"
            report += "The save file may use internal item IDs that need to be decoded separately.\n\n"
    
    # Technical information
    if 'technical_info' in game_data and game_data['technical_info']:
        report += "🔧 TECHNICAL INFORMATION:\n"
        report += "=" * 40 + "\n"
        tech = game_data['technical_info']
        for key, value in tech.items():
            report += f"{key.replace('_', ' ').title()}: {value}\n"
        report += "\n"
    
    return report

def extract_readable_strings(data_bytes, min_length=4):
    """Extract readable strings from binary data"""
    try:
        # Try different encodings
        encodings = ['utf-8', 'utf-16le', 'utf-16be', 'latin-1', 'ascii', 'cp1252']
        
        results = {}
        
        for encoding in encodings:
            try:
                decoded = data_bytes.decode(encoding, errors='ignore')
                
                # Extract strings that are mostly printable
                strings = []
                current_string = ""
                
                for char in decoded:
                    if char.isprintable() or char.isspace():
                        current_string += char
                    else:
                        if len(current_string.strip()) >= min_length:
                            strings.append(current_string.strip())
                        current_string = ""
                
                # Add the last string if it's long enough
                if len(current_string.strip()) >= min_length:
                    strings.append(current_string.strip())
                
                # Filter out strings that are mostly non-ASCII or look like binary
                readable_strings = []
                for s in strings:
                    if len(s) >= min_length:
                        # Check if string has reasonable amount of readable characters
                        printable_ratio = sum(1 for c in s if c.isprintable() and ord(c) < 127) / len(s)
                        if printable_ratio > 0.7:  # At least 70% ASCII printable
                            readable_strings.append(s)
                
                if readable_strings:
                    results[encoding] = {
                        'strings': readable_strings,
                        'total_length': sum(len(s) for s in readable_strings),
                        'count': len(readable_strings)
                    }
                    
            except Exception:
                continue
        
        return results
    except Exception:
        return {}

def try_parse_as_json_like(text):
    """Try to extract JSON-like structures from mixed text"""
    try:
        # Look for JSON-like patterns
        json_patterns = [
            r'\{[^{}]*\}',  # Simple objects
            r'\[[^\[\]]*\]',  # Simple arrays
        ]
        
        potential_json = []
        for pattern in json_patterns:
            matches = re.finditer(pattern, text, re.DOTALL)
            for match in matches:
                try:
                    json_str = match.group(0)
                    parsed = json.loads(json_str)
                    potential_json.append({
                        'json': json_str,
                        'parsed': parsed,
                        'start': match.start(),
                        'end': match.end()
                    })
                except:
                    continue
        
        return potential_json
    except:
        return []

def analyze_lenchar_structure(raw_bytes):
    """Detailed analysis of .lenchar file structure with enhanced text extraction"""
    analysis = {
        'layers': [],
        'total_size': len(raw_bytes),
        'magic_header': None,
        'successful_decode': False,
        'final_content': None,
        'extracted_strings': None,
        'encoding_analysis': None,
        'game_data': None,
        'binary_analysis': None
    }
    
    current_data = raw_bytes
    layer_count = 0
    
    try:
        # Layer 1: Check for FLOW header
        if current_data.startswith(b'FLOW'):
            analysis['magic_header'] = 'FLOW'
            
            # Check version byte
            if len(current_data) > 4:
                version = current_data[4]
                analysis['layers'].append({
                    'layer': layer_count,
                    'type': 'FLOW_header',
                    'version': version,
                    'size_before': len(current_data),
                    'header_bytes': current_data[:8].hex()
                })
                
                # Remove FLOW header (4 bytes) + version (1 byte) = 5 bytes
                current_data = current_data[5:]
                layer_count += 1
        
        # Layer 2: Try gzip decompression
        try:
            # Check if it starts with gzip magic number
            if current_data.startswith(b'\x1f\x8b'):
                analysis['layers'].append({
                    'layer': layer_count,
                    'type': 'gzip_compressed',
                    'size_before': len(current_data),
                    'magic_bytes': current_data[:2].hex()
                })
                decompressed = gzip.decompress(current_data)
                current_data = decompressed
                layer_count += 1
            else:
                # Try to decompress anyway (some gzip doesn't have proper headers)
                try:
                    decompressed = gzip.decompress(current_data)
                    analysis['layers'].append({
                        'layer': layer_count,
                        'type': 'gzip_compressed_no_header',
                        'size_before': len(current_data),
                        'size_after': len(decompressed)
                    })
                    current_data = decompressed
                    layer_count += 1
                except:
                    pass
        except Exception as e:
            analysis['layers'].append({
                'layer': layer_count,
                'type': 'gzip_failed',
                'error': str(e),
                'first_bytes': current_data[:16].hex()
            })
        
        # Layer 3: Try zlib decompression (alternative compression)
        try:
            decompressed = zlib.decompress(current_data)
            analysis['layers'].append({
                'layer': layer_count,
                'type': 'zlib_compressed',
                'size_before': len(current_data),
                'size_after': len(decompressed)
            })
            current_data = decompressed
            layer_count += 1
        except:
            pass
        
        # Layer 4: Try base64 decoding
        try:
            # Check if it looks like base64
            try:
                decoded_test = base64.b64decode(current_data, validate=True)
                analysis['layers'].append({
                    'layer': layer_count,
                    'type': 'base64_encoded',
                    'size_before': len(current_data),
                    'size_after': len(decoded_test)
                })
                current_data = decoded_test
                layer_count += 1
            except:
                pass
        except:
            pass
        
        # Now we have the final decoded data - perform advanced binary analysis
        binary_analysis = analyze_game_save_structure(current_data)
        analysis['binary_analysis'] = binary_analysis
        
        # NEW: Try binary parsing for Len's Island data
        binary_game_data = parse_lens_island_binary(current_data)
        
        # Try multiple approaches for content extraction
        
        # Try 1: Check for JSON structure
        try:
            text_content = current_data.decode('utf-8', errors='replace')
            json_data = json.loads(text_content)
            analysis['layers'].append({
                'layer': layer_count,
                'type': 'json_data',
                'size': len(text_content),
                'keys': list(json_data.keys()) if isinstance(json_data, dict) else 'array'
            })
            
            # Parse as Len's Island game data (both text and binary)
            text_game_data = parse_lens_island_data(text_content)
            
            # Merge binary and text parsing results
            merged_game_data = merge_game_data(binary_game_data, text_game_data)
            formatted_game_data = format_lens_island_data(merged_game_data)
            binary_report = format_game_save_analysis(binary_analysis)
            
            analysis['successful_decode'] = True
            analysis['final_content'] = f"{binary_report}\n\n{formatted_game_data}\n\n=== RAW JSON ===\n{json.dumps(json_data, indent=2)}"
            analysis['game_data'] = merged_game_data
            return analysis
        except:
            pass
        
        # Try 2: Binary game save file analysis with enhanced Len's Island parsing
        meaningful_strings = binary_analysis.get('readable_content', {}).get('meaningful_strings', [])
        unity_strings = [s['content'] for s in binary_analysis.get('unity_strings', [])]
        
        # If we have binary game data or meaningful strings, use that
        if (not binary_game_data.get('error') and 
            (binary_game_data.get('location') or binary_game_data.get('character_data') or binary_game_data.get('inventory'))):
            
            # Also try text parsing on meaningful strings
            all_meaningful = meaningful_strings + unity_strings
            combined_text = '\n'.join(all_meaningful)
            text_game_data = parse_lens_island_data(combined_text)
            
            # Merge binary and text parsing results
            merged_game_data = merge_game_data(binary_game_data, text_game_data)
            formatted_game_data = format_lens_island_data(merged_game_data)
            binary_report = format_game_save_analysis(binary_analysis)
            
            analysis['layers'].append({
                'layer': layer_count,
                'type': 'binary_game_save_enhanced',
                'binary_data_found': bool(binary_game_data.get('location') or binary_game_data.get('character_data')),
                'meaningful_strings': len(meaningful_strings),
                'unity_strings': len(unity_strings)
            })
            
            final_content = f"{binary_report}\n\n{formatted_game_data}"
            
            # Add coordinate information if found
            coords = binary_analysis.get('binary_structures', {}).get('coordinates', [])
            if coords:
                final_content += f"\n\n📍 ADDITIONAL COORDINATE DATA:\n"
                final_content += "=" * 50 + "\n"
                for i, coord in enumerate(coords[:10]):
                    final_content += f"Position {i+1}: X={coord['x']:.2f}, Y={coord['y']:.2f}, Z={coord['z']:.2f}\n"
            
            analysis['successful_decode'] = True
            analysis['final_content'] = final_content
            analysis['game_data'] = merged_game_data
            return analysis
        
        elif meaningful_strings or unity_strings:
            # Fallback: use text-based analysis if binary parsing didn't work
            # Combine all meaningful strings for game data parsing
            all_meaningful = meaningful_strings + unity_strings
            combined_text = '\n'.join(all_meaningful)
            
            # Parse as Len's Island game data
            game_data = parse_lens_island_data(combined_text)
            formatted_game_data = format_lens_island_data(game_data)
            binary_report = format_game_save_analysis(binary_analysis)
            
            analysis['layers'].append({
                'layer': layer_count,
                'type': 'text_based_fallback',
                'meaningful_strings': len(meaningful_strings),
                'unity_strings': len(unity_strings),
                'total_strings': len(all_meaningful)
            })
            
            final_content = f"{binary_report}\n\n{formatted_game_data}"
            
            # Add coordinate information if found
            coords = binary_analysis.get('binary_structures', {}).get('coordinates', [])
            if coords:
                final_content += f"\n\n📍 ADDITIONAL COORDINATE DATA:\n"
                final_content += "=" * 50 + "\n"
                for i, coord in enumerate(coords[:10]):
                    final_content += f"Position {i+1}: X={coord['x']:.2f}, Y={coord['y']:.2f}, Z={coord['z']:.2f}\n"
            
            analysis['successful_decode'] = True
            analysis['final_content'] = final_content
            analysis['game_data'] = game_data
            return analysis
        
        # Try 3: Mixed binary/text data - extract readable strings (fallback)
        string_analysis = extract_readable_strings(current_data)
        analysis['extracted_strings'] = string_analysis
        
        if string_analysis:
            # Find the best encoding based on extracted strings
            best_encoding = None
            best_score = 0
            
            for encoding, data in string_analysis.items():
                score = data['total_length'] * data['count']
                if score > best_score:
                    best_score = score
                    best_encoding = encoding
            
            if best_encoding and string_analysis[best_encoding]['strings']:
                strings = string_analysis[best_encoding]['strings']
                
                # Combine all strings for game data parsing
                combined_text = '\n'.join(strings)
                
                # Parse as Len's Island game data
                game_data = parse_lens_island_data(combined_text)
                formatted_game_data = format_lens_island_data(game_data)
                binary_report = format_game_save_analysis(binary_analysis)
                
                # Try to find JSON-like structures in the strings
                json_candidates = []
                for string in strings:
                    json_like = try_parse_as_json_like(string)
                    json_candidates.extend(json_like)
                
                # Create a readable representation
                readable_content = f"{binary_report}\n\n{formatted_game_data}\n\n"
                readable_content += f"=== EXTRACTED READABLE CONTENT ({best_encoding.upper()}) ===\n\n"
                
                if json_candidates:
                    readable_content += "JSON-LIKE STRUCTURES FOUND:\n"
                    for i, candidate in enumerate(json_candidates):
                        readable_content += f"\n--- JSON Structure {i+1} ---\n"
                        readable_content += json.dumps(candidate['parsed'], indent=2)
                        readable_content += "\n"
                
                readable_content += f"\nEXTRACTED STRINGS ({len(strings)} found):\n"
                readable_content += "=" * 50 + "\n\n"
                
                # Show only first 20 strings to avoid overwhelming output
                for i, string in enumerate(strings[:20]):
                    readable_content += f"String {i+1} ({len(string)} chars):\n"
                    readable_content += string + "\n"
                    readable_content += "-" * 30 + "\n"
                
                if len(strings) > 20:
                    readable_content += f"\n... and {len(strings) - 20} more strings ...\n"
                
                analysis['layers'].append({
                    'layer': layer_count,
                    'type': 'mixed_binary_text',
                    'best_encoding': best_encoding,
                    'strings_found': len(strings),
                    'json_structures': len(json_candidates)
                })
                analysis['successful_decode'] = True
                analysis['final_content'] = readable_content
                analysis['encoding_analysis'] = string_analysis
                analysis['game_data'] = game_data
                return analysis
        
        # Try 4: Check if it's mostly readable as UTF-8 with some binary
        try:
            text_content = current_data.decode('utf-8', errors='replace')
            # Check if it's mostly readable text
            readable_chars = sum(1 for c in text_content if c.isprintable() or c.isspace())
            if readable_chars / len(text_content) > 0.3:  # At least 30% readable
                # Parse as Len's Island game data
                game_data = parse_lens_island_data(text_content)
                formatted_game_data = format_lens_island_data(game_data)
                binary_report = format_game_save_analysis(binary_analysis)
                
                analysis['layers'].append({
                    'layer': layer_count,
                    'type': 'mixed_text_binary',
                    'size': len(text_content),
                    'readability': readable_chars / len(text_content)
                })
                
                # Clean up the text a bit
                cleaned_text = re.sub(r'[^\x20-\x7E\n\r\t]', '', text_content)
                
                final_content = f"{binary_report}\n\n{formatted_game_data}\n\n"
                final_content += f"=== MIXED BINARY/TEXT CONTENT ===\n\nReadability: {readable_chars/len(text_content)*100:.1f}%\n\n{cleaned_text[:2000]}"
                
                analysis['successful_decode'] = True
                analysis['final_content'] = final_content
                analysis['game_data'] = game_data
                return analysis
        except:
            pass
        
        # If we get here, it's complex binary data
        analysis['layers'].append({
            'layer': layer_count,
            'type': 'complex_binary_data',
            'size': len(current_data),
            'first_32_bytes': current_data[:32].hex()
        })
        
        # Show binary analysis even if we couldn't extract meaningful game data
        binary_report = format_game_save_analysis(binary_analysis)
        
        # Try to extract any readable strings from binary data and parse as game data
        extracted = extract_readable_strings(current_data, min_length=3)
        if extracted:
            # Try to parse game data from extracted strings
            all_strings = []
            for encoding_data in extracted.values():
                all_strings.extend(encoding_data['strings'])
            
            combined_text = '\n'.join(all_strings)
            game_data = parse_lens_island_data(combined_text)
            formatted_game_data = format_lens_island_data(game_data)
            
            binary_content = f"{binary_report}\n\n{formatted_game_data}\n\n"
            binary_content += f"=== ADDITIONAL STRING EXTRACTION ===\n"
            binary_content += f"Binary data ({len(current_data)} bytes) with extracted strings:\n\n"
            
            for encoding, data in extracted.items():
                if data['strings']:
                    binary_content += f"=== {encoding.upper()} STRINGS ===\n"
                    for string in data['strings'][:10]:  # First 10 strings only
                        binary_content += f"• {string}\n"
                    binary_content += f"\n({data['count']} total strings)\n\n"
            
            analysis['final_content'] = binary_content
            analysis['extracted_strings'] = extracted
            analysis['game_data'] = game_data
        else:
            analysis['final_content'] = f"{binary_report}\n\nBinary data ({len(current_data)} bytes)\n\nNo readable strings found."
        
        analysis['successful_decode'] = True  # We always provide some analysis
        
    except Exception as e:
        analysis['layers'].append({
            'layer': layer_count,
            'type': 'error',
            'error': str(e)
        })
        analysis['final_content'] = f"Error during analysis: {str(e)}"
    
    return analysis

def merge_game_data(binary_data, text_data):
    """Merge results from binary and text parsing"""
    if binary_data.get('error') and text_data.get('error'):
        return {'error': 'Both binary and text parsing failed'}
    
    # Start with binary data if available
    if not binary_data.get('error'):
        merged = binary_data.copy()
    else:
        merged = text_data.copy()
    
    # Merge location data (prefer binary data for coordinates)
    if not binary_data.get('error') and binary_data.get('location'):
        merged['location'] = binary_data['location']
    elif text_data.get('location'):
        merged['location'] = text_data['location']
    
    # Merge character data (combine both sources)
    char_data = {}
    if not binary_data.get('error') and binary_data.get('character_data'):
        char_data.update(binary_data['character_data'])
    if text_data.get('character_data'):
        char_data.update(text_data['character_data'])
    if char_data:
        merged['character_data'] = char_data
    
    # Merge inventory (combine and deduplicate)
    inventory = []
    if not binary_data.get('error') and binary_data.get('inventory'):
        inventory.extend(binary_data['inventory'])
    if text_data.get('inventory'):
        inventory.extend(text_data['inventory'])
    if inventory:
        merged['inventory'] = list(set(inventory))  # Remove duplicates
    
    # Keep technical info from binary parsing
    if not binary_data.get('error') and binary_data.get('technical_info'):
        merged['technical_info'] = binary_data['technical_info']
    
    return merged

def try_decode_lenchar(raw_bytes):
    """Try multiple methods to decode .lenchar files with detailed analysis"""
    results = {
        'success': False,
        'decoded_text': '',
        'format_detected': 'unknown',
        'error': '',
        'raw_preview': '',
        'structure_analysis': None
    }
    
    # Create raw preview (first 200 bytes as hex)
    results['raw_preview'] = raw_bytes[:200].hex() if len(raw_bytes) > 0 else ''
    
    # Perform detailed structure analysis
    structure = analyze_lenchar_structure(raw_bytes)
    results['structure_analysis'] = structure
    
    if structure['successful_decode']:
        results['success'] = True
        results['decoded_text'] = structure['final_content']
        
        # Determine format based on layers
        layer_types = [layer['type'] for layer in structure['layers']]
        if 'FLOW_header' in layer_types and 'gzip_compressed' in layer_types:
            if 'mixed_binary_text' in layer_types:
                results['format_detected'] = 'flow_gzip_mixed'
            elif 'mixed_text_binary' in layer_types:
                results['format_detected'] = 'flow_gzip_text'
            else:
                results['format_detected'] = 'flow_gzip'
        elif 'json_data' in layer_types:
            results['format_detected'] = 'json'
        elif 'mixed_binary_text' in layer_types:
            results['format_detected'] = 'mixed_binary_text'
        else:
            results['format_detected'] = 'multi_layer'
            
        return results
    
    # Fallback to original methods if structure analysis fails
    try:
        # Method 1: Try plain text (UTF-8)
        try:
            decoded = raw_bytes.decode('utf-8')
            results['success'] = True
            results['decoded_text'] = decoded
            results['format_detected'] = 'plain_text'
            return results
        except UnicodeDecodeError:
            pass
        
        # Method 2: Try FLOW + gzip (Enhanced)
        try:
            if raw_bytes.startswith(b"FLOW"):
                # More flexible FLOW parsing
                version_byte = raw_bytes[4] if len(raw_bytes) > 4 else 1
                header_size = 5  # FLOW + version
                
                # Try different header sizes in case there's padding
                for offset in [5, 6, 7, 8]:
                    try:
                        if len(raw_bytes) > offset:
                            gzipped = raw_bytes[offset:]
                            decompressed = gzip.decompress(gzipped)
                            
                            # Try different encodings for the decompressed data
                            for encoding in ['utf-8', 'latin-1', 'utf-16le', 'cp1252']:
                                try:
                                    decoded = decompressed.decode(encoding, errors='replace')
                                    # Check if this encoding gives us more readable text
                                    readable_chars = sum(1 for c in decoded if c.isprintable() or c.isspace())
                                    if readable_chars / len(decoded) > 0.3:
                                        results['success'] = True
                                        results['decoded_text'] = f"Decoded using {encoding}:\n\n{decoded}"
                                        results['format_detected'] = f'flow_gzip_{encoding}_offset_{offset}'
                                        return results
                                except:
                                    continue
                    except:
                        continue
        except Exception:
            pass
        
        # Method 3: Try raw gzip with different encodings
        try:
            decompressed = gzip.decompress(raw_bytes)
            for encoding in ['utf-8', 'latin-1', 'utf-16le', 'cp1252']:
                try:
                    decoded = decompressed.decode(encoding, errors='replace')
                    readable_chars = sum(1 for c in decoded if c.isprintable() or c.isspace())
                    if readable_chars / len(decoded) > 0.3:
                        results['success'] = True
                        results['decoded_text'] = f"Decoded using {encoding}:\n\n{decoded}"
                        results['format_detected'] = f'raw_gzip_{encoding}'
                        return results
                except:
                    continue
        except Exception:
            pass
        
        # Fallback - show as hex dump with structure analysis
        hex_content = f"Multi-layer analysis completed.\n\nStructure Analysis:\n"
        for i, layer in enumerate(structure['layers']):
            hex_content += f"Layer {i}: {layer['type']}\n"
            if 'size_before' in layer:
                hex_content += f"  Size: {layer.get('size_before', 'unknown')} bytes\n"
            if 'error' in layer:
                hex_content += f"  Error: {layer['error']}\n"
            hex_content += "\n"
        
        if structure.get('extracted_strings'):
            hex_content += "\nExtracted strings found - try viewing the structure analysis for details.\n\n"
        
        hex_content += f"\nFinal data ({len(raw_bytes)} bytes):\n{format_hex_dump(raw_bytes[:1000])}"
        
        results['decoded_text'] = hex_content
        results['format_detected'] = 'complex_binary'
        results['success'] = True
        return results
        
    except Exception as e:
        results['error'] = f"Critical error during decoding: {str(e)}"
        results['decoded_text'] = f"Error: {str(e)}\n\nRaw hex data:\n{raw_bytes[:500].hex()}"
        return results

def format_hex_dump(data_bytes, bytes_per_line=16):
    """Format binary data as a readable hex dump"""
    if not data_bytes:
        return "No data"
    
    hex_dump = ""
    for i in range(0, len(data_bytes), bytes_per_line):
        chunk = data_bytes[i:i+bytes_per_line]
        
        # Address
        hex_dump += f"{i:08x}: "
        
        # Hex values
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        hex_dump += f"{hex_part:<{bytes_per_line*3}} "
        
        # ASCII representation
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        hex_dump += f"|{ascii_part}|\n"
    
    return hex_dump

def encode_for_display(data_bytes):
    """Convert binary data to a readable format for display"""
    return f"Binary Data ({len(data_bytes)} bytes):\n{format_hex_dump(data_bytes[:500])}"

def create_lenchar_from_text(text, format_type='auto'):
    """Create a .lenchar file from text using the specified format"""
    if format_type == 'plain_text':
        return text.encode('utf-8')
    elif format_type in ['flow_gzip', 'flow_gzip_mixed', 'flow_gzip_text'] or format_type.startswith('flow_gzip_'):
        # Enhanced FLOW format
        data_bytes = text.encode('utf-8')
        gz = gzip.compress(data_bytes)
        return b"FLOW\x01" + gz
    elif format_type == 'raw_gzip' or format_type.startswith('raw_gzip_'):
        data_bytes = text.encode('utf-8')
        return gzip.compress(data_bytes)
    elif format_type == 'zlib':
        data_bytes = text.encode('utf-8')
        return zlib.compress(data_bytes)
    elif format_type == 'base64_gzip':
        data_bytes = text.encode('utf-8')
        gz = gzip.compress(data_bytes)
        return base64.b64encode(gz)
    elif format_type == 'base64_text':
        data_bytes = text.encode('utf-8')
        return base64.b64encode(data_bytes)
    elif format_type == 'json':
        # Try to parse as JSON for pretty formatting
        try:
            json_obj = json.loads(text)
            formatted_json = json.dumps(json_obj, indent=2)
            return formatted_json.encode('utf-8')
        except json.JSONDecodeError:
            return text.encode('utf-8')
    else:
        # Auto-detect or default to plain text
        return text.encode('utf-8')

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        f = request.files.get('file')
        if not f:
            return redirect(request.url)
        
        raw = f.read()
        # Store only essential data in session to avoid cookie size issues
        session['original_raw'] = base64.b64encode(raw).decode('utf-8')
        session['filename'] = f.filename
        
        # Try to decode the file
        decode_result = try_decode_lenchar(raw)
        
        if decode_result['success']:
            session['original_decoded'] = decode_result['decoded_text']
            session['format_detected'] = decode_result['format_detected']
            # Don't store large structure analysis in session
            encoded_display = encode_for_display(raw)
            
            return render_template('editor.html', 
                                 decoded=decode_result['decoded_text'], 
                                 encoded=encoded_display,
                                 filename=f.filename,
                                 format_detected=decode_result['format_detected'],
                                 raw_preview=decode_result['raw_preview'],
                                 structure_analysis=decode_result.get('structure_analysis'))
        else:
            error_msg = f"Could not decode file: {decode_result['error']}"
            return render_template('upload.html', error=error_msg)
    
    return render_template('upload.html')

@app.route('/update_encoded', methods=['POST'])
def update_encoded():
    """Update the encoded view when decoded text changes"""
    decoded_text = request.json.get('decoded', '')
    format_type = session.get('format_detected', 'auto')
    
    try:
        # Create new encoded version based on detected format
        new_raw = create_lenchar_from_text(decoded_text, format_type)
        encoded_display = encode_for_display(new_raw)
        return jsonify({'encoded': encoded_display, 'success': True, 'format': format_type})
    except Exception as e:
        return jsonify({'error': str(e), 'success': False})

@app.route('/reset', methods=['POST'])
def reset():
    """Reset to original content"""
    if 'original_decoded' in session:
        decoded = session['original_decoded']
        raw = base64.b64decode(session['original_raw'])
        encoded_display = encode_for_display(raw)
        format_detected = session.get('format_detected', 'unknown')
        
        # Re-analyze the file for structure analysis
        decode_result = try_decode_lenchar(raw)
        structure_analysis = decode_result.get('structure_analysis')
        
        return jsonify({
            'decoded': decoded,
            'encoded': encoded_display,
            'format': format_detected,
            'structure_analysis': structure_analysis,
            'success': True
        })
    return jsonify({'error': 'No original content found', 'success': False})

@app.route('/save_decoded', methods=['POST'])
def save_decoded():
    text = request.form.get('decoded', '')
    buf = io.BytesIO(text.encode('utf-8'))
    buf.seek(0)
    return send_file(buf,
                     as_attachment=True,
                     download_name='decoded.txt',
                     mimetype='text/plain')

@app.route('/save_encoded', methods=['POST'])
def save_encoded():
    text = request.form.get('decoded', '')
    format_type = session.get('format_detected', 'auto')
    
    try:
        new_file = create_lenchar_from_text(text, format_type)
        buf = io.BytesIO(new_file)
        buf.seek(0)
        
        # Determine file extension based on format
        if format_type == 'json':
            filename = 'modified.json'
            mimetype = 'application/json'
        elif format_type in ['plain_text']:
            filename = 'modified.txt'
            mimetype = 'text/plain'
        else:
            filename = 'modified.lenchar'
            mimetype = 'application/octet-stream'
        
        return send_file(buf,
                         as_attachment=True,
                         download_name=filename,
                         mimetype=mimetype)
    except Exception as e:
        return jsonify({'error': str(e), 'success': False})

@app.route('/analyze', methods=['POST'])
def analyze_file():
    """Analyze uploaded file and show detailed information"""
    f = request.files.get('file')
    if not f:
        return jsonify({'error': 'No file provided', 'success': False})
    
    raw = f.read()
    
    # Perform detailed structure analysis
    structure = analyze_lenchar_structure(raw)
    
    analysis = {
        'filename': f.filename,
        'size': len(raw),
        'hex_preview': raw[:100].hex() if raw else '',
        'potential_formats': [],
        'structure_analysis': structure
    }
    
    # Check various format signatures
    if raw.startswith(b'FLOW'):
        analysis['potential_formats'].append('FLOW format (Len\'s Island)')
    if raw.startswith(b'\x1f\x8b'):
        analysis['potential_formats'].append('GZIP compressed')
    if raw.startswith(b'PK'):
        analysis['potential_formats'].append('ZIP archive')
    if raw.startswith(b'UNITY'):
        analysis['potential_formats'].append('Unity save file')
    
    try:
        raw.decode('utf-8')
        analysis['potential_formats'].append('UTF-8 text')
    except UnicodeDecodeError:
        pass
    
    try:
        json.loads(raw.decode('utf-8', errors='ignore'))
        analysis['potential_formats'].append('JSON data')
    except:
        pass
    
    return jsonify({'analysis': analysis, 'success': True})

@app.route('/new')
def new_file():
    """Clear session and redirect to upload page"""
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True, port=5001)