require 'json'
require 'sqlite3'
module EverpaySandbox
  class Idempotency
    def initialize(path)
      raise ArgumentError, 'A persistent database path is required' if path.empty? || path == ':memory:' || path.start_with?('file:')

      File.open(path, File::CREAT | File::WRONLY, 0o600) {}
      @db = SQLite3::Database.new(path)
      @db.busy_timeout = 5000
      @db.execute('PRAGMA synchronous = FULL')
      @db.execute(<<~SQL)
        CREATE TABLE IF NOT EXISTS requests (
          request_key TEXT PRIMARY KEY,
          fingerprint TEXT NOT NULL,
          reply TEXT
        )
      SQL
      @mutex = Mutex.new
    end

    def run(key, fingerprint, pending)
      existing = @mutex.synchronize do
        @db.execute('INSERT INTO requests (request_key, fingerprint) VALUES (?, ?) ON CONFLICT DO NOTHING', [key, fingerprint])
        @db.get_first_row('SELECT fingerprint, reply FROM requests WHERE request_key = ?', [key]) if @db.changes.zero?
      end

      if existing
        return [409, { success: false, response_code: 'IDEMPOTENCY_CONFLICT' }] unless existing.first == fingerprint

        return existing.last ? JSON.parse(existing.last, symbolize_names: true) : pending
      end

      # A reservation without a reply may have reached the processor. Keep it reserved after a crash.
      result = yield
      @mutex.synchronize { @db.execute('UPDATE requests SET reply = ? WHERE request_key = ?', [JSON.generate(result), key]) }
      result
    end

    def close
      @db.close
    end
  end
end
