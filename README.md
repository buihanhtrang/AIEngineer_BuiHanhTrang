# AIEngineer_BuiHanhTrang
# AI Security Analysis Agent

AI Agent phân tích cảnh báo an toàn thông tin sử dụng GPT-4o mini và các công cụ bảo mật.

## Tính năng

- **Phân tích URL**: Sử dụng VirusTotal và Domain Reputation
- **Phân tích IP**: Sử dụng AbuseIPDB
- **Phân tích File Path**: Phân tích đường dẫn file nghi ngờ
- **Phân tích Domain**: Kiểm tra danh tiếng domain
- **AI Analysis**: Sử dụng GPT-4o mini để phân tích tổng hợp

## Công cụ sử dụng

1. **VirusTotal API**: Phân tích URL và file hash
2. **AbuseIPDB API**: Kiểm tra danh tiếng IP
3. **Domain Reputation Analysis**: Phân tích domain tự phát triển
4. **File Path Analysis**: Phân tích đường dẫn file nghi ngờ
5. **GPT-4o mini**: Phân tích tổng hợp và đưa ra kết luận

## Cài đặt và chạy

### Yêu cầu

- Docker & Docker Compose
- OpenAI API Key
- VirusTotal API Key (tùy chọn)
- AbuseIPDB API Key (tùy chọn)

### Hướng dẫn cài đặt

1. **Clone repository và chuẩn bị file**:
```bash
# Tạo thư mục project
mkdir AIagent
cd AIagent

# Tạo các file cần thiết (app.py, Dockerfile, requirements.txt, docker-compose.yml)
```

2. **Cấu hình environment**:
```bash
cp .env
# Chỉnh sửa .env file với API keys của bạn
```

3. **Build và chạy với Docker**:
```bash
# Build image
docker-compose build

# Chạy service
docker-compose up -d

# Kiểm tra logs
docker-compose logs -f
```

4. **Kiểm tra health**:
```bash
curl http://localhost:8989/health
```

## API Usage

### Endpoint: `/analysis_agent`

**Method**: POST  
**Port**: 8989  
**Content-Type**: application/json

### Request Format

```json
{
  "query": "Kiểm tra URL https://viettelstore.vn/"
}
```

### Response Format

```json
{
  "analysis": "Phân tích chi tiết về đối tượng được kiểm tra...",
  "result": "CLEAN|ABNORMAL|UNKNOWN"
}
```

### Các loại kết quả

- **CLEAN**: Không có dấu hiệu nguy hiểm
- **ABNORMAL**: Có dấu hiệu độc hại hoặc nghi ngờ cao
- **UNKNOWN**: Không đủ thông tin để xác định

## Ví dụ sử dụng

### 1. Kiểm tra URL

```bash
curl -X POST http://localhost:8989/analysis_agent \
  -H "Content-Type: application/json" \
  -d '{"query": "Kiểm tra URL https://viettelstore.vn/"}'
```

### 2. Kiểm tra IP

```bash
curl -X POST http://localhost:8989/analysis_agent \
  -H "Content-Type: application/json" \
  -d '{"query": "Kiểm tra IP 8.8.8.8"}'
```

### 3. Kiểm tra File Path

```bash
curl -X POST http://localhost:8989/analysis_agent \
  -H "Content-Type: application/json" \
  -d '{"query": "Check C:\\Windows\\NetworkDistribution\\svchost.exe"}'
```

### 4. Kiểm tra Domain

```bash
curl -X POST http://localhost:8989/analysis_agent \
  -H "Content-Type: application/json" \
  -d '{"query": "Kiểm tra domain vietel.com.vn"}'
```

## Kết quả test case

### Test Case 1: URL Clean
```json
{
  "query": "Kiểm tra URL https://viettelstore.vn/"
}
```
**Expected Result**: CLEAN

### Test Case 2: File Path Abnormal
```json
{
  "query": "Check C:\\Windows\\NetworkDistribution\\svchost.exe"
}
```
**Expected Result**: ABNORMAL

## Cấu trúc thư mục

```
security-agent/
├── app.py              # Main application
├── Dockerfile          # Docker configuration
├── requirements.txt    # Python dependencies
├── docker-compose.yml  # Docker compose configuration
├── .env.example       # Environment variables example
└── README.md          # Documentation
```

## Troubleshooting

### Lỗi thường gặp

1. **API Key không hợp lệ**:
   - Kiểm tra lại API keys trong file `.env`
   - Đảm bảo OpenAI API key là bắt buộc

2. **Container không start**:
   - Kiểm tra port 8989 có bị conflict không
   - Xem logs: `docker-compose logs -f`

3. **Timeout từ external APIs**:
   - Một số APIs có thể chậm, agent sẽ xử lý gracefully

### Monitoring

- Health check: `GET http://localhost:8989/health`
- Logs: `docker-compose logs -f security-agent`

## Security Notes

- Không lưu trữ API keys trong code
- Sử dụng environment variables cho configuration
- Container chạy với non-root user
- Implement proper error handling cho external APIs