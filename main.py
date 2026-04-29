from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
import os
from . import database
from . import config_generator

# Initialize App
app = FastAPI(title="Proxy Manager")

# Initialize DB
database.init_db()

MAX_SOURCE_LIST_CONTENT_BYTES = 5000


def _summarize_source_content(source):
    item = dict(source)
    content = item.get("content") or ""
    item["content_size"] = len(content.encode("utf-8"))
    item["content_preview"] = content[:120] + ("..." if len(content) > 120 else "")
    has_sensitive_content = False

    if item.get("type") == "protonvpn":
        try:
            import json
            data = json.loads(content or "{}")
            if isinstance(data, dict) and data.get("format") == "protonvpn.compact.v1":
                count = len(data.get("servers") or [])
                stats = data.get("stats") if isinstance(data.get("stats"), dict) else {}
                raw_count = stats.get("raw_servers")
                unique_count = stats.get("unique_endpoints") or count
                if not raw_count and count:
                    endpoint_keys = {
                        (
                            item.get("server"),
                            item.get("port"),
                            item.get("public_key"),
                        )
                        for item in data.get("servers", [])
                        if isinstance(item, dict)
                    }
                    unique_count = len(endpoint_keys)
                    raw_count = count if unique_count != count else None
                fetched_at = data.get("fetched_at") or ""
                if raw_count and raw_count != unique_count:
                    item["content_preview"] = (
                        f"Proton compact cache · {unique_count} endpoints · "
                        f"{raw_count} logical nodes"
                    )
                else:
                    item["content_preview"] = f"Proton compact cache · {count} nodes"
                if fetched_at:
                    item["content_preview"] += f" · {fetched_at[:19]}"
                has_sensitive_content = isinstance(data.get("auth"), dict)
                if has_sensitive_content:
                    item["content_preview"] += " · saved session"
            elif isinstance(data, dict) and isinstance(data.get("wireguard_configs"), list):
                item["content_preview"] = (
                    f"Proton WireGuard cache · {len(data['wireguard_configs'])} nodes"
                )
                has_sensitive_content = isinstance(data.get("auth"), dict)
                if has_sensitive_content:
                    item["content_preview"] += " · saved session"
        except Exception:
            pass

    if has_sensitive_content or item["content_size"] > MAX_SOURCE_LIST_CONTENT_BYTES:
        item["content"] = ""
        item["content_omitted"] = True
    else:
        item["content_omitted"] = False

    return item

# Models
class SourceCreate(BaseModel):
    name: str
    type: str # 'subscription', 'text', 'vless'
    content: str
    selection: Optional[dict] = None
    
class SourceUpdate(BaseModel):
    enabled: bool

class SourceEdit(BaseModel):
    name: str
    type: str
    content: str
    selection: Optional[dict] = None

class GenerateRequest(BaseModel):
    output_path: Optional[str] = None
    restart_service: bool = False
    service_name: str = "clash-meta"

class ProtonFetchRequest(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    twofa_code: Optional[str] = None
    name: Optional[str] = "ProtonVPN"
    existing_content: Optional[str] = None
    auth_uid: Optional[str] = None
    auth_token: Optional[str] = None
    access_token: Optional[str] = None
    session_id: Optional[str] = None
    cookie_header: Optional[str] = None
    app_version: Optional[str] = None
    api_base_url: Optional[str] = None
    dedupe_endpoints: Optional[bool] = None

# Routes
@app.get("/api/sources")
def get_sources():
    return [_summarize_source_content(source) for source in database.get_all_sources()]

@app.post("/api/protonvpn/fetch")
def fetch_protonvpn(req: ProtonFetchRequest):
    try:
        from . import protonvpn_provider
        content, nodes = protonvpn_provider.fetch_content(
            req.username,
            req.password,
            req.twofa_code,
            req.name or "ProtonVPN",
            existing_content=req.existing_content,
            auth_uid=req.auth_uid,
            auth_token=req.auth_token,
            access_token=req.access_token,
            session_id=req.session_id,
            cookie_header=req.cookie_header,
            app_version=req.app_version,
            api_base_url=req.api_base_url,
            dedupe_endpoints=req.dedupe_endpoints,
        )
        stats = {}
        try:
            import json
            compact = json.loads(content or "{}")
            if isinstance(compact, dict) and isinstance(compact.get("stats"), dict):
                stats = compact["stats"]
        except Exception:
            stats = {}
        preview = []
        for node in nodes:
            preview.append({
                "node_key": node["node_key"],
                "name": node["name"],
                "type": node["type"],
                "server": node["server"],
                "port": node["port"],
                "metadata": node.get("metadata", {}),
                "selected": True,
            })
        return {
            "status": "success",
            "content": content,
            "nodes": preview,
            "count": len(preview),
            "stats": stats,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/sources")
def add_source(source: SourceCreate):
    content_to_save = source.content
    source_type = source.type
    
    # Handle Xray Import
    if source.type == 'xray':
        try:
            from . import proxy_parser 
            proxies, port = proxy_parser.parse_xray_json(source.content)
            if not proxies:
                 raise HTTPException(status_code=400, detail="No valid Method found in Xray config")
                 
            # Convert to YAML
            import yaml
            content_to_save = yaml.dump({"proxies": proxies}, allow_unicode=True, sort_keys=False)
            source_type = 'yaml' # Save as YAML
            
            # Save port mapping if found
            if port:
                first_proxy_name = proxies[0]["name"]
                database.save_port_mapping(first_proxy_name, port)
                
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to parse Xray config: {str(e)}")

    new_id = database.add_source(source.name, source_type, content_to_save, source.selection)
    return {"id": new_id, "status": "added"}

@app.delete("/api/sources/{id}")
def delete_source(id: int):
    database.delete_source(id)
    return {"status": "deleted"}

@app.post("/api/sources/{id}/toggle")
def toggle_source(id: int, update: SourceUpdate):
    database.update_source_status(id, update.enabled)
    return {"status": "updated"}

@app.put("/api/sources/{id}")
def edit_source(id: int, source: SourceEdit):
    content_to_save = source.content
    source_type = source.type
    
    # Handle Xray Import (same as add)
    if source.type == 'xray':
        try:
            from . import proxy_parser 
            proxies, port = proxy_parser.parse_xray_json(source.content)
            if not proxies:
                 raise HTTPException(status_code=400, detail="No valid Method found in Xray config")
                 
            import yaml
            content_to_save = yaml.dump({"proxies": proxies}, allow_unicode=True, sort_keys=False)
            source_type = 'yaml'
            
            if port:
                first_proxy_name = proxies[0]["name"]
                database.save_port_mapping(first_proxy_name, port)
                
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to parse Xray config: {str(e)}")
    
    database.update_source(id, source.name, source_type, content_to_save, source.selection)
    return {"status": "updated"}

@app.post("/api/sources/preview")
def preview_source(source: SourceCreate):
    try:
        from . import source_providers
        nodes = source_providers.preview_nodes(
            source.type,
            source.content,
            source.selection,
            source.name,
        )
        return {"status": "success", "nodes": nodes, "count": len(nodes)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/sources/{id}")
def get_source(id: int):
    source = database.get_source_by_id(id)
    if not source:
        raise HTTPException(status_code=404, detail="Source not found")
    return source

@app.get("/api/sources/{id}/preview")
def preview_saved_source(id: int):
    source = database.get_source_by_id(id)
    if not source:
        raise HTTPException(status_code=404, detail="Source not found")
    try:
        from . import source_providers
        nodes = source_providers.preview_nodes(
            source["type"],
            source["content"],
            source.get("selection"),
            source.get("name", ""),
        )
        return {"status": "success", "nodes": nodes, "count": len(nodes)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/mappings")
def get_mappings():
    return database.get_all_mappings()

@app.get("/api/mappings/duplicates")
def get_duplicates():
    return database.get_duplicate_ports()

@app.delete("/api/mappings/{proxy_name:path}")
def delete_mapping(proxy_name: str):
    database.delete_port_mapping(proxy_name)
    return {"status": "deleted"}

class MappingUpdate(BaseModel):
    port: int
    proxy_name: str | None = None

@app.put("/api/mappings/{proxy_name:path}")
def update_mapping(proxy_name: str, update: MappingUpdate):
    new_name = update.proxy_name
    if new_name and new_name != proxy_name:
        database.delete_port_mapping(proxy_name)
        database.save_port_mapping(new_name, update.port)
    else:
        database.update_port_mapping(proxy_name, update.port)
    return {"status": "updated"}

class ImportRequest(BaseModel):
    path: Optional[str] = "config.yaml"

@app.post("/api/mappings/import")
async def import_mappings_from_config(file: UploadFile = File(...)):
    try:
        content = (await file.read()).decode("utf-8")
        from . import proxy_parser 
        mappings = proxy_parser.extract_mappings_from_config(content)
        count = 0
        for name, port in mappings.items():
            database.save_port_mapping(name, port)
            count += 1
            
        return {"status": "success", "imported_count": count, "message": f"Successfully imported {count} mappings from {file.filename}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.post("/api/generate")
def generate_config(req: GenerateRequest):
    path = req.output_path or "../config.yaml"
    try:
        count, out_path, issues = config_generator.generate_config_file(path)
        msg = f"Generated {count} proxies to {out_path}."
        
        restart_msg = ""
        if req.restart_service:
            success, r_msg = config_generator.restart_mihomo_service(req.service_name)
            if success:
                restart_msg = f" Service {req.service_name} restarted."
            else:
                restart_msg = f" Service restart failed: {r_msg}"
        
        # Build issues summary
        issues_summary = []
        for issue in issues:
            reason_text = {
                'disabled': '已禁用',
                'empty': '无有效代理',
                'error': '解析错误'
            }.get(issue['reason'], issue['reason'])
            issues_summary.append({
                'name': issue['source_name'],
                'type': issue['source_type'],
                'reason': reason_text,
                'detail': issue['detail']
            })
                
        return {
            "status": "success", 
            "message": msg + restart_msg,
            "proxy_count": count,
            "issues": issues_summary
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Static Files
import os
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
