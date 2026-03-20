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

# Models
class SourceCreate(BaseModel):
    name: str
    type: str # 'subscription', 'text', 'vless'
    content: str
    
class SourceUpdate(BaseModel):
    enabled: bool

class SourceEdit(BaseModel):
    name: str
    type: str
    content: str

class GenerateRequest(BaseModel):
    output_path: Optional[str] = None
    restart_service: bool = False
    service_name: str = "clash-meta"

# Routes
@app.get("/api/sources")
def get_sources():
    return database.get_all_sources()

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

    new_id = database.add_source(source.name, source_type, content_to_save)
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
    
    database.update_source(id, source.name, source_type, content_to_save)
    return {"status": "updated"}

@app.get("/api/sources/{id}")
def get_source(id: int):
    source = database.get_source_by_id(id)
    if not source:
        raise HTTPException(status_code=404, detail="Source not found")
    return source

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
