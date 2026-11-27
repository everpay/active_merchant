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
      @db.execute(<<~SQL)
        CREATE TABLE IF NOT EXISTS captures (
          capture_id TEXT PRIMARY KEY,
          merchant_account TEXT NOT NULL,
          reference TEXT NOT NULL,
          currency TEXT NOT NULL,
          amount INTEGER NOT NULL,
          processor_amount INTEGER NOT NULL,
          enrollment TEXT,
          status TEXT NOT NULL DEFAULT 'pending',
          UNIQUE (merchant_account, reference)
        )
      SQL
      @db.execute(<<~SQL)
        CREATE TABLE IF NOT EXISTS purchase_declines (
          capture_id TEXT PRIMARY KEY,
          amount INTEGER NOT NULL,
          currency TEXT NOT NULL,
          response_code TEXT NOT NULL
        )
      SQL
      @mutex = Mutex.new
    end

    def record_authorization(capture_id, attributes)
      values = attributes.values_at(:account, :reference, :amount, :processor_amount, :currency)
      enrollment = attributes[:enrollment]
      @mutex.synchronize do
        @db.execute(<<~SQL, [capture_id, *values, enrollment && JSON.generate(enrollment)])
          INSERT INTO captures (capture_id, merchant_account, reference, amount, processor_amount, currency, enrollment)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        SQL
      end
    end

    def capture_status(capture_id)
      row = @mutex.synchronize do
        @db.get_first_row('SELECT status, reference, amount, currency, enrollment FROM captures WHERE capture_id = ?', [capture_id])
      end
      return decline_status(capture_id) unless row

      status, reference, amount, currency, enrollment = row
      { status:, authorization: reference, amount:, currency:,
        enrollment: status == 'captured' && enrollment ? JSON.parse(enrollment) : nil }
    end

    def record_decline(capture_id, amount, currency, code)
      @mutex.synchronize do
        @db.execute('INSERT INTO purchase_declines VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING', [capture_id, amount, currency, code])
      end
    end

    def record_capture_events(events)
      @mutex.synchronize do
        @db.transaction do
          events.each do |status, account, reference, amount, currency|
            @db.execute(<<~SQL, [status, account, reference, amount, currency])
              UPDATE captures SET status = ?
              WHERE merchant_account = ? AND reference = ? AND processor_amount = ? AND currency = ?
                AND status <> 'capture_review'
            SQL
          end
        end
      end
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

    private

    def decline_status(capture_id)
      row = @mutex.synchronize do
        @db.get_first_row('SELECT amount, currency, response_code FROM purchase_declines WHERE capture_id = ?', [capture_id])
      end
      return unless row

      amount, currency, response_code = row
      { status: 'declined', amount:, currency:, response_code: }
    end
  end
end
