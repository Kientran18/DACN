# Rule Sigma tự thêm (local)

Đặt tệp `.yml` Sigma do bạn viết hoặc chép từ nguồn khác vào thư mục này, rồi thêm một mục `origin: local` vào
`src/detection/sigma/manifest.yaml` (kèm `license` của rule). Hướng dẫn: `docs/implementation/SIGMA_RULES.md` mục 6.
Rule local cũng là `synthetic_only` cho tới khi được kiểm chứng; không bao giờ kích hoạt response.
