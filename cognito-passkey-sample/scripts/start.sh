#!/bin/bash
# Flask アプリを起動する（スクリーンキャプチャ・開発用）
#
# 使い方:
#   bash scripts/start.sh
#
# 事前準備:
#   1. .env を用意する（.env.example を参照）
#   2. 依存パッケージをインストールする:
#        python3 -m venv venv
#        ./venv/bin/pip install -r requirements.txt

set -e
cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "Error: .env が見つかりません。Cognito の設定値を記載した .env を作成してください。" >&2
  exit 1
fi

if [ ! -d venv ]; then
  echo "Error: venv が見つかりません。以下を実行してください:" >&2
  echo "  python3 -m venv venv && ./venv/bin/pip install -r requirements.txt" >&2
  exit 1
fi

echo "Flask アプリを起動します: http://localhost:5000"
exec ./venv/bin/python app.py
