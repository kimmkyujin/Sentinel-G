import os
from dotenv import load_dotenv

# .env 파일 로드 (환경변수 자동 적용)
load_dotenv()

import sys
import json
import logging
import asyncio
import time
import subprocess
from contextlib import asynccontextmanager
from typing import Dict, Any, List


from fastapi import FastAPI, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Python 3.14 호환성을 위해 google._upb._message 모듈 임포트 차단
sys.modules["google._upb._message"] = None
sys.modules["google._upb"] = None
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"

import firebase_admin
from firebase_admin import credentials, firestore

import google.generativeai as genai

import sentinel_g

# ==============================================================================
# 1. 로깅 설정 (산업 현장 표준)
# ==============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("Sentinel-G-Agent")

# ==============================================================================
# 2. Gemini API 설정 및 GCP 연동
# ==============================================================================
google_api_key = os.environ.get("GOOGLE_API_KEY")
if not google_api_key:
    logger.warning("GOOGLE_API_KEY가 설정되지 않았습니다. .env 파일을 확인하세요.")
else:
    genai.configure(api_key=google_api_key)

key_path = os.path.join(os.getcwd(), "key.json")
if os.path.exists(key_path):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = key_path
    try:
        with open(key_path, "r") as f:
            key_data = json.load(f)
            project_id = key_data.get("project_id")
            if project_id:
                sentinel_g.PROJECT_ID = project_id
                logger.info(f"GCP Project ID 설정 완료: {project_id}")
    except Exception as e:
        logger.error(f"key.json 읽기 실패: {e}")
else:
    project_id = os.environ.get("GCP_PROJECT_ID")
    if project_id:
        sentinel_g.PROJECT_ID = project_id
        logger.info(f"GCP Project ID (Env) 설정 완료: {project_id}")

# ==============================================================================
# 2.5 Firebase Firestore 설정
# ==============================================================================
db = None
try:
    if not firebase_admin._apps:
        if os.path.exists(key_path):
            cred = credentials.Certificate(key_path)
            firebase_admin.initialize_app(cred)
        else:
            firebase_admin.initialize_app()
    db = firestore.client()
    logger.info("Firebase Firestore 초기화 완료")
except Exception as e:
    logger.error(f"Firebase 초기화 실패: {e}")

def update_firestore(port: int, status: str, **kwargs):
    if db is None:
        return
    try:
        doc_ref = db.collection("ports").document(str(port))
        data = {"status": status, "port": port}
        data.update(kwargs)
        doc_ref.set(data, merge=True)
    except Exception as e:
        logger.error(f"Firestore 업데이트 실패 (포트 {port}): {e}")

# ==============================================================================
# 3. 전역 상태 관리 및 WebSocket 연결 관리
# ==============================================================================
ACTIVE_PORTS: Dict[int, Dict[str, Any]] = {}
CHAT_SESSIONS = {}

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_alert(self, message_data: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message_data)
            except Exception as e:
                logger.error(f"웹소켓 전송 오류: {e}")
                self.disconnect(connection)

manager = ConnectionManager()

MAIN_LOOP = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global MAIN_LOOP
    MAIN_LOOP = asyncio.get_running_loop()
    yield
    for port, data in list(ACTIVE_PORTS.items()):
        if data.get("expire_task"): data["expire_task"].cancel()
        if data.get("notify_task"): data["notify_task"].cancel()
        if data.get("process"):
            try:
                data["process"].terminate()
            except Exception:
                pass
    ACTIVE_PORTS.clear()

app = FastAPI(title="Sentinel-G Cognitive Security Agent (Gemini)", version="3.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def serve_ui():
    return FileResponse("static/index.html")

@app.websocket("/ws/alert")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

class ChatRequest(BaseModel):
    session_id: str = Field(..., description="사용자 대화 세션 ID")
    message: str = Field(..., description="사용자 입력 메시지")

class ChatResponse(BaseModel):
    response: str
    status: str = Field(description="현재 상태")

# ==============================================================================
# 4. 백그라운드 타이머 로직
# ==============================================================================
async def notify_timer(port: int, rule_name: str, notify_time_ms: int, remain_minutes: int, session_id: str):
    try:
        current_time = int(time.time() * 1000)
        sleep_ms = notify_time_ms - current_time
        if sleep_ms > 0:
            await asyncio.sleep(sleep_ms / 1000.0)
            
        msg = f"⚠️ 경고: 방화벽 규칙({port}번 포트)이 {remain_minutes}분 후 자동 닫힙니다. 연장하시겠습니까?"
        logger.info(f"[Timer Task] {msg}")
        
        alert_data = {
            "type": "alert",
            "port": port,
            "message": msg
        }
        await manager.broadcast_alert(alert_data)
        
        if session_id in CHAT_SESSIONS:
            chat_session = CHAT_SESSIONS[session_id]
            try:
                chat_session.history.append({
                    "role": "user",
                    "parts": [f"[시스템 내부 알림] 사용자에게 다음 메시지가 출력되었습니다: '{msg}'. 방금 알림이 나간 포트는 {port}번입니다. 사용자가 번호를 생략하고 연장해달라고 하면 {port}번을 연장하세요."]
                })
                chat_session.history.append({
                    "role": "model",
                    "parts": [f"알겠습니다. {port}번 포트 연장 요청을 대기하겠습니다."]
                })
            except Exception as e:
                logger.error(f"히스토리 주입 실패: {e}")
                
    except asyncio.CancelledError:
        pass

async def expire_timer(port: int, rule_name: str, expire_time_ms: int, session_id: str):
    try:
        current_time = int(time.time() * 1000)
        sleep_ms = expire_time_ms - current_time
        if sleep_ms > 0:
            await asyncio.sleep(sleep_ms / 1000.0)
            
        logger.info(f"[Timer Task] {port}번 포트 만료 시간 도달. 자동 삭제.")
        try:
            await asyncio.to_thread(sentinel_g.delete_firewall_rule, rule_name)
        except Exception as e:
            logger.error(f"{port}번 포트 방화벽 규칙 삭제 중 오류 발생(무시됨): {e}")
        
        alert_data = {
            "type": "alert",
            "port": port,
            "message": f"⏳ {port}번 포트의 방화벽이 자동 폐쇄되었습니다."
        }
        await manager.broadcast_alert(alert_data)
        
        # Firestore 기록 (자동 폐쇄 시)
        await asyncio.to_thread(
            update_firestore, port, "closed", closed_at=int(time.time() * 1000)
        )
        
        if session_id in CHAT_SESSIONS:
            chat_session = CHAT_SESSIONS[session_id]
            try:
                chat_session.history.append({
                    "role": "user",
                    "parts": [f"[시스템 내부 알림] {port}번 포트의 방화벽 만료 시간이 도달하여 자동으로 폐쇄되었습니다. 이제 이 포트는 닫힌 상태입니다."]
                })
                chat_session.history.append({
                    "role": "model",
                    "parts": [f"네, {port}번 포트가 자동 폐쇄된 것을 확인했습니다."]
                })
            except Exception as e:
                logger.error(f"히스토리 주입 실패: {e}")
        
    except asyncio.CancelledError:
        pass
    finally:
        data = ACTIVE_PORTS.pop(port, None)
        if data and data.get("process"):
            try:
                data["process"].terminate()
            except Exception:
                pass

def setup_port_timers(port: int, rule_name: str, duration_minutes: int, notify_minutes: int, session_id: str):
    if port in ACTIVE_PORTS:
        old_data = ACTIVE_PORTS[port]
        if old_data.get("expire_task"): old_data["expire_task"].cancel()
        if old_data.get("notify_task"): old_data["notify_task"].cancel()
        
    current_time = int(time.time() * 1000)
    expire_time = current_time + (duration_minutes * 60 * 1000)
    
    notify_task = None
    notify_time = expire_time - (notify_minutes * 60 * 1000)
    if notify_time > current_time:
        notify_task = asyncio.run_coroutine_threadsafe(
            notify_timer(port, rule_name, notify_time, notify_minutes, session_id),
            MAIN_LOOP
        )
        
    expire_task = asyncio.run_coroutine_threadsafe(
        expire_timer(port, rule_name, expire_time, session_id),
        MAIN_LOOP
    )
    
    ACTIVE_PORTS[port] = {
        "rule_name": rule_name,
        "expire_task": expire_task,
        "notify_task": notify_task,
        "session_id": session_id,
        "duration": duration_minutes,
        "notify_minutes": notify_minutes,
        "expire_time": expire_time,
        "start_time": current_time,
        "total_open_time": duration_minutes
    }

# ==============================================================================
# 5. Function Calling 도구
# ==============================================================================
def open_gcp_firewall(ip: str, port: int, duration: int, purpose: str, notify_minutes: int = 1) -> str:
    """지정된 IP, 포트, 시간, 용도를 기반으로 GCP 방화벽을 엽니다."""
    port = int(port)
    duration = int(duration)
    session_id = getattr(open_gcp_firewall, "current_session_id", "")
    if not notify_minutes or notify_minutes <= 0: notify_minutes = 1
    notify_minutes = int(notify_minutes)
        
    logger.info(f"[Function Call] open_gcp_firewall - Port:{port}, Duration:{duration}")
    try:
        if sentinel_g.find_firewall_rule_by_port(port):
            return json.dumps({"status": "error", "message": f"해당 포트({port})는 이미 열려있습니다. 연장 기능을 사용하세요."})
            
        rule_data = sentinel_g.create_firewall_rule(ip, port, duration, notify_minutes)
        rule_name = rule_data.get("ruleName")
        setup_port_timers(port, rule_name, duration, notify_minutes, session_id)
        
        # 서브 프로세스(동적 포트 바인딩) 실행 (Ubuntu 리눅스 환경 대응)
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.py")
        proc = subprocess.Popen(["python3", script_path, "--host", "0.0.0.0", "--port", str(port)])
        if port in ACTIVE_PORTS:
            ACTIVE_PORTS[port]["process"] = proc
        
        # Firestore 기록 (열릴 때)
        opened_at = int(time.time() * 1000)
        expire_at = ACTIVE_PORTS[port]["expire_time"]
        warn_at = expire_at - (notify_minutes * 60 * 1000)
        update_firestore(
            port, "open",
            opened_at=opened_at,
            expire_at=expire_at,
            warn_at=warn_at
        )
        
        return json.dumps({"status": "success", "message": f"{port}번 포트가 {duration}분간 개방되었습니다.", "port": port})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

def close_gcp_firewall(port: int) -> str:
    """지정된 포트 번호에 해당하는 방화벽 규칙을 즉시 닫고 삭제합니다."""
    port = int(port)
    logger.info(f"[Function Call] close_gcp_firewall - Port: {port}")
    try:
        rule_name = sentinel_g.find_firewall_rule_by_port(port)
        if not rule_name:
            return json.dumps({"status": "success", "message": "해당 포트는 이미 닫혀 있습니다."})
            
        if port in ACTIVE_PORTS:
            data = ACTIVE_PORTS.pop(port)
            if data.get("expire_task"): data["expire_task"].cancel()
            if data.get("notify_task"): data["notify_task"].cancel()
            if data.get("process"):
                try:
                    data["process"].terminate()
                except Exception:
                    pass
        
        sentinel_g.delete_firewall_rule(rule_name)
        
        # Firestore 기록 (즉시 닫을 때)
        update_firestore(
            port, "closed",
            closed_at=int(time.time() * 1000)
        )
        
        return json.dumps({"status": "success", "message": f"{port}번 포트를 즉시 닫았습니다."})
    except Exception as e:
        return json.dumps({"status": "error", "message": f"시스템 오류: {str(e)}"})

def modify_firewall_time(port: int, extra_minutes: int) -> str:
    """이미 열려있는 방화벽의 유지 시간에 주어진 분(minutes)만큼 추가로 연장합니다."""
    port = int(port)
    extra_minutes = int(extra_minutes)
    session_id = getattr(modify_firewall_time, "current_session_id", "")
    
    try:
        rule_name = sentinel_g.find_firewall_rule_by_port(port)
        if not rule_name:
            return json.dumps({"status": "error", "message": "해당 포트는 현재 열려있지 않습니다."})
            
        current_expire_time = ACTIVE_PORTS.get(port, {}).get("expire_time", int(time.time() * 1000))
        current_time = int(time.time() * 1000)
        remain_minutes = max(0, current_expire_time - current_time) // 60000
        new_duration = remain_minutes + extra_minutes
        
        logger.info(f"[Function Call] modify_firewall_time - Port: {port}, Add: {extra_minutes}m, New Duration: {new_duration}m")
        
        notify_minutes = ACTIVE_PORTS.get(port, {}).get("notify_minutes", 1)
        setup_port_timers(port, rule_name, new_duration, notify_minutes, session_id)
        
        # Firestore 기록 (연장 시)
        expire_at = ACTIVE_PORTS[port]["expire_time"]
        warn_at = expire_at - (notify_minutes * 60 * 1000)
        update_firestore(
            port, "open",
            expire_at=expire_at,
            warn_at=warn_at,
            updated_at=int(time.time() * 1000)
        )
        
        return json.dumps({"status": "success", "message": f"{port}번 포트가 {extra_minutes}분 추가 연장되어 남은 시간이 총 {new_duration}분으로 설정되었습니다."})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

def modify_notify_time(port: int, notify_minutes: int) -> str:
    """이미 열려있는 방화벽의 사전 알림 시간을 변경합니다."""
    port = int(port)
    notify_minutes = int(notify_minutes)
    session_id = getattr(modify_notify_time, "current_session_id", "")
    logger.info(f"[Function Call] modify_notify_time - Port: {port}, Notify: {notify_minutes}m")
    try:
        if port not in ACTIVE_PORTS:
            return json.dumps({"status": "error", "message": "해당 포트는 시스템에 타이머가 없습니다."})
            
        data = ACTIVE_PORTS[port]
        expire_time = data["expire_time"]
        current_time = int(time.time() * 1000)
        
        notify_time = expire_time - (notify_minutes * 60 * 1000)
        if notify_time <= current_time:
            return json.dumps({"status": "error", "message": f"만료 시간까지 {notify_minutes}분 미만으로 남아 알림을 설정할 수 없습니다."})
            
        if data.get("notify_task"):
            data["notify_task"].cancel()
            
        notify_task = asyncio.run_coroutine_threadsafe(
            notify_timer(port, data["rule_name"], notify_time, notify_minutes, session_id),
            MAIN_LOOP
        )
        data["notify_task"] = notify_task
        data["notify_minutes"] = notify_minutes
        
        # Firestore 기록 (알림 시간 변경 시)
        warn_at = expire_time - (notify_minutes * 60 * 1000)
        update_firestore(
            port, "open",
            warn_at=warn_at,
            updated_at=int(time.time() * 1000)
        )
        
        return json.dumps({"status": "success", "message": f"{port}번 포트의 알림 시간이 닫히기 {notify_minutes}분 전으로 성공적으로 변경되었습니다."})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


def check_remaining_time(port: int = 0) -> str:
    """특정 포트의 남은 방화벽 개방 시간을 조회합니다. 포트를 모를 경우 0을 전달하세요."""
    if port is None:
        port = 0
    port = int(port)
    if port == 0:
        if len(ACTIVE_PORTS) == 1:
            port = list(ACTIVE_PORTS.keys())[0]
        else:
            return json.dumps({"status": "error", "message": "어떤 포트 번호의 남은 시간을 조회할까요?"})
            
    if port not in ACTIVE_PORTS:
        return json.dumps({"status": "error", "message": "해당 포트는 현재 열려있지 않습니다."})
        
    data = ACTIVE_PORTS[port]
    start_time_ms = data.get("start_time", int(time.time() * 1000))
    total_open_time_minutes = data.get("total_open_time", data.get("duration", 0))
    current_time_ms = int(time.time() * 1000)
    
    remain_ms = (start_time_ms + (total_open_time_minutes * 60 * 1000)) - current_time_ms
    
    if remain_ms <= 0:
        return json.dumps({"status": "error", "message": "해당 포트는 현재 열려있지 않습니다."})
        
    remain_sec = remain_ms // 1000
    minutes = remain_sec // 60
    seconds = remain_sec % 60
    
    return json.dumps({"status": "success", "message": f"{port}번 포트는 현재 {minutes}분 {seconds}초 후에 닫힐 예정입니다."})


system_instruction = """
너는 산업 현장의 인프라 보안을 관리하는 지능형 에이전트야. 사용자와 자연스럽게 상호작용해.

1. 방화벽 개방 (`open_gcp_firewall`):
   - IP, 포트번호, 시간, 용도가 명시되어야 해.
   - 알림 시간 미지정 시 시스템 기본값(1분)이 적용됨.
2. 방화벽 즉시 닫기 (`close_gcp_firewall`):
   - "해당 포트는 이미 닫혀 있습니다" 반환 시 그대로 안내할 것.
3. 방화벽 시간 변경/연장 (`modify_firewall_time`):
   - "X번 포트 Y분간 연장해줘" 또는 "Y분 추가해줘"라고 하면 추가할 시간(Y)을 전달할 것. 이 함수는 기존 남은 시간에 Y분을 더해주는 역할을 함.
   - 단, 사용자가 포트 번호를 생략하고 "5분 연장해줘"라고 할 때, 이전 대화 맥락에 "[시스템 내부 알림]"으로 특정 포트 경고가 뜬 직후라면 반드시 그 포트를 타겟팅하여 연장 함수를 호출해야 해. "어떤 포트 번호인가요?"라고 되묻지 말 것!
4. 방화벽 알림 시간 변경 (`modify_notify_time`):
   - "X번 포트 알림 시간을 Y분으로 바꿔줘"라고 하면 호출할 것.
5. 방화벽 남은 시간 조회 (`check_remaining_time`):
   - "X번 포트 남은 시간 얼마야?" 또는 "언제 닫혀?" 라고 물어보면 호출해.
   - 사용자가 포트 번호를 생략하고 물어본다면 `port=0`으로 전달해서 호출해.
6. 시스템 기능 외의 요청 처리:
   - 위 5가지 기능 이외의 시스템 설정 변경이나 알 수 없는 명령을 요구하면 "지원되지 않는 명령입니다."라고 명확히 답변할 것.
"""

try:
    model = genai.GenerativeModel(
        model_name="gemini-3.1-flash-lite",
        system_instruction=system_instruction,
        tools=[open_gcp_firewall, close_gcp_firewall, modify_firewall_time, modify_notify_time, check_remaining_time]
    )
except Exception as e:
    logger.error(f"Gemini 초기화 실패: {e}")
    model = None

# ==============================================================================
# 6. API 엔드포인트
# ==============================================================================
@app.post("/api/v1/chat", response_model=ChatResponse)
async def chat_endpoint(req: ChatRequest):
    session_id = req.session_id
    user_msg = req.message

    if model is None:
        raise HTTPException(status_code=500, detail="Gemini 모델이 초기화되지 않았습니다.")

    if session_id not in CHAT_SESSIONS:
        CHAT_SESSIONS[session_id] = model.start_chat(enable_automatic_function_calling=False)
    
    chat_session = CHAT_SESSIONS[session_id]
    
    # 래퍼 변수 주입 (세션 ID)
    open_gcp_firewall.current_session_id = session_id
    modify_firewall_time.current_session_id = session_id
    modify_notify_time.current_session_id = session_id

    try:
        response = await asyncio.to_thread(chat_session.send_message, user_msg)
        
        function_call = None
        for part in response.parts:
            if part.function_call:
                function_call = part.function_call
                break
        
        if function_call:
            func_name = function_call.name
            args = {k: v for k, v in function_call.args.items()}
            
            # 함수 매핑
            tool_funcs = {
                "open_gcp_firewall": open_gcp_firewall,
                "close_gcp_firewall": close_gcp_firewall,
                "modify_firewall_time": modify_firewall_time,
                "modify_notify_time": modify_notify_time,
                "check_remaining_time": check_remaining_time
            }
            
            if func_name in tool_funcs:
                func = tool_funcs[func_name]
                func_result_str = await asyncio.to_thread(func, **args)
                result_data = json.loads(func_result_str)
                
                final_response = await asyncio.to_thread(
                    chat_session.send_message,
                    [{"function_response": {"name": func_name, "response": {"result": result_data}}}]
                )
                
                try:
                    reply_text = final_response.text
                except ValueError:
                    reply_text = result_data.get("message", "요청하신 작업을 완료했습니다.")
                return ChatResponse(response=reply_text, status="EXECUTED")
            else:
                return ChatResponse(response="알 수 없는 함수 호출이 요청되었습니다.", status="ERROR")
        else:
            try:
                reply_text = response.text
            except ValueError:
                reply_text = "처리 완료되었습니다."
            return ChatResponse(response=reply_text, status="CHAT")

    except Exception as e:
        logger.error(f"[{session_id}] 처리 중 오류: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=False)

