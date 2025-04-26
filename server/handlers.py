from fastapi import APIRouter, BackgroundTasks
from .scanner import run_scan # Относительный импорт, хер знает что значит, сказали так надо
from scanner.core.scanners.crawler import Crawler

router = APIRouter()
scanner = Crawler()

@router.post("/scan")
async def start_scan(
    target: str,
    scan_type: str = "full",
    bg: BackgroundTasks = BackgroundTasks()
):
    bg.add_task(run_scan, target, scan_type)
    return {"message": "Scan started", "target": target}

@router.get("/results/{scan_id}")
async def get_results(scan_id: str):
    return scanner.get_results(scan_id)