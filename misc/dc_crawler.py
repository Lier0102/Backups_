import requests
from bs4 import BeautifulSoup
from datetime import datetime
import time
import csv
import sys

def get_valid_url(gallery_id, headers):
    url_patterns = [
        f"https://gall.dcinside.com/mgallery/board/lists/?id={gallery_id}",
        f"https://gall.dcinside.com/mini/board/lists/?id={gallery_id}",
        f"https://gall.dcinside.com/board/lists/?id={gallery_id}"
    ]
    
    for url in url_patterns:
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200 and (gallery_id in response.text or "gall_tit" in response.text):
                return url
        except:
            continue
    return None

def parse_dc_date(date_str):
    now = datetime.now()
    date_str = date_str.strip()
    try:
        if len(date_str) > 15:
            return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        if ":" in date_str and "." not in date_str:
            return datetime.strptime(f"{now.strftime('%Y-%m-%d')} {date_str}", "%Y-%m-%d %H:%M")
        parts = date_str.split('.')
        if len(parts) == 2:
            return datetime.strptime(f"{now.year}.{date_str}", "%Y.%m.%d")
        if len(parts) == 3:
            year = parts[0]
            if len(year) == 2: year = "20" + year
            return datetime.strptime(f"{year}.{parts[1]}.{parts[2]}", "%Y.%m.%d")
    except:
        return None
    return None

def get_post_content(url, headers):
    """게시글 링크에 접속하여 본문 내용을 가져옵니다."""
    try:
        # 게시글 접속 시 Referer를 갤러리 리스트로 설정하여 차단 확률 감소
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code != 200:
            return "[내용을 불러올 수 없습니다]"
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 일반/마이너/미니 갤러리 본문 영역 선택자
        content_div = soup.select_one('.write_div') or soup.select_one('.writing_view_box')
        
        if content_div:
            # 텍스트만 추출하고 불필요한 공백 정리
            return content_div.get_text(separator="\n", strip=True)
        return "[본문 내용 없음]"
    except Exception as e:
        return f"[오류 발생: {e}]"

def crawl_dcinside(gallery_id, start_date_str, end_date_str):
    try:
        start_date = datetime.strptime(start_date_str, "%Y-%m-%d")
        end_date = datetime.combine(datetime.strptime(end_date_str, "%Y-%m-%d"), datetime.max.time())
    except ValueError:
        print("날짜 형식이 잘못되었습니다. YYYY-MM-DD 형식을 사용하세요.")
        return

    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    }

    print(f"[{gallery_id}] 접속 시도 중...")
    base_url = get_valid_url(gallery_id, headers)
    
    if not base_url:
        print(f"오류: '{gallery_id}' 갤러리를 찾을 수 없습니다.")
        return

    print(f"연결 성공: {base_url}")
    print(f"수집 기간: {start_date_str} ~ {end_date_str}")
    print("리스트 수집 후 본문을 순차적으로 가져옵니다. 잠시만 기다려주세요.")

    post_list = []
    page = 1
    stop_crawling = False

    # 1단계: 게시글 리스트 수집
    while not stop_crawling:
        url = f"{base_url}&page={page}"
        try:
            response = requests.get(url, headers=headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            rows = soup.select('tr.ub-content') or soup.select('.list_tbody tr')

            if not rows:
                break

            found_any_in_page = False
            for row in rows:
                num_el = row.select_one('.gall_num, .num')
                if not num_el or not num_el.text.strip().isdigit():
                    continue

                title_el = row.select_one('.gall_tit a, .tit a')
                date_el = row.select_one('.gall_date, .date')
                if not title_el or not date_el: continue
                
                title = title_el.text.strip()
                link = title_el['href']
                if not link.startswith('http'):
                    link = "https://gall.dcinside.com" + link
                
                raw_date = date_el.get('title') or date_el.text.strip()
                post_date = parse_dc_date(raw_date)
                
                if not post_date: continue
                if post_date > end_date: continue
                if post_date < start_date:
                    stop_crawling = True
                    break
                
                post_list.append({
                    'date': post_date.strftime("%Y-%m-%d %H:%M:%S"),
                    'title': title,
                    'link': link
                })
                found_any_in_page = True

            print(f" 리스트 수집 중: {page}페이지 완료 (누적 {len(post_list)}개)", end="\r")
            page += 1
            if page > 300: break
            time.sleep(0.5)
        except:
            break

    print(f"\n\n2단계: 총 {len(post_list)}개의 본문 수집을 시작합니다...")

    # 2단계: 각 게시글 본문 수집
    results = []
    for i, post in enumerate(post_list):
        # 본문 가져오기 전 Referer 업데이트 (해당 게시글의 리스트 페이지)
        headers["Referer"] = base_url
        content = get_post_content(post['link'], headers)
        
        results.append([post['date'], post['title'], content, post['link']])
        
        print(f" [{i+1}/{len(post_list)}] 수집 중: {post['title'][:20]}...", end="\r")
        
        # 차단 방지를 위해 매 글마다 짧은 대기 (본문 수집은 리스트보다 더 주의해야 함)
        time.sleep(0.8)

    print("\n" + "="*50)
    if results:
        filename = f"dc_{gallery_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(filename, 'w', encoding='utf-8-sig', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['날짜', '제목', '본문', '링크'])
            writer.writerows(results)
        print(f"결과: {len(results)}개 수집 완료 -> {filename}")
    else:
        print("결과: 해당 기간의 글을 찾지 못했습니다.")

if __name__ == "__main__":
    gal_id = input("갤러리 ID: ").strip()
    s_date = input("시작일 (YYYY-MM-DD): ").strip()
    e_date = input("종료일 (YYYY-MM-DD): ").strip()
    crawl_dcinside(gal_id, s_date, e_date)
