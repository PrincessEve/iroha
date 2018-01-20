/**
 * Copyright Soramitsu Co., Ltd. 2017 All Rights Reserved.
 * http://soramitsu.co.jp
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ametsuchi/impl/postgres_wsv_command.hpp"

#include <exception>
#include <iterator>
#include <numeric>

namespace iroha {
  namespace ametsuchi {

    PostgresWsvCommand::PostgresWsvCommand(pqxx::nontransaction &transaction)
        : transaction_(transaction), log_(logger::log("PostgresWsvCommand")) {}

    template <typename T>
    std::string try_quote(PostgresWsvCommand *that, const T &s) noexcept {
      try {
        return that->transaction_.quote(s);
      } catch (std::bad_alloc &e) {
        that->log_->error("Unable to alloc: {}", e.what());
        std::terminate();
      }
    }

    bool PostgresWsvCommand::insertRole(const std::string &role_name) {
      try {
        transaction_.exec("INSERT INTO role(role_id) VALUES ("
                          + try_quote(this, role_name) + ");");
      } catch (const std::exception &e) {
        log_->error(e.what());
        return false;
      }
      return true;
    }

    bool PostgresWsvCommand::insertAccountRole(const std::string &account_id,
                                               const std::string &role_name) {
      try {
        transaction_.exec(
            "INSERT INTO account_has_roles(account_id, role_id) VALUES ("
            + try_quote(this, account_id) + ", " + try_quote(this, role_name)
            + ");");
      } catch (const std::exception &e) {
        log_->error(e.what());
        return false;
      }
      return true;
    }

    bool PostgresWsvCommand::deleteAccountRole(const std::string &account_id,
                                               const std::string &role_name) {
      try {
        transaction_.exec("DELETE FROM account_has_roles WHERE account_id="
                          + try_quote(this, account_id)
                          + "AND role_id=" + try_quote(this, role_name) + ";");
      } catch (const std::exception &e) {
        log_->error(e.what());
        return false;
      }
      return true;
    }

    bool PostgresWsvCommand::insertRolePermissions(
        const std::string &role_id, const std::set<std::string> &permissions) {
      auto entry = [this, &role_id](auto permission) {
        return "(" + try_quote(this, role_id) + ", "
            + try_quote(this, permission) + ")";
      };
      try {
        transaction_.exec(
            "INSERT INTO role_has_permissions(role_id, permission_id) VALUES "
            + std::accumulate(
                  std::next(permissions.begin()),
                  permissions.end(),
                  entry(*permissions.begin()),
                  [&entry](auto acc, auto x) { return acc + ", " + entry(x); })
            + ";");
      } catch (const std::exception &e) {
        log_->error(e.what());
        return false;
      }
      return true;
    }

    bool PostgresWsvCommand::insertAccountGrantablePermission(
        const std::string &permittee_account_id,
        const std::string &account_id,
        const std::string &permission_id) {
      try {
        transaction_.exec(
            "INSERT INTO "
            "account_has_grantable_permissions(permittee_account_id, "
            "account_id, permission_id) VALUES ("
            + try_quote(this, permittee_account_id) + ", "
            + try_quote(this, account_id) + ", "
            + try_quote(this, permission_id) + ");");
      } catch (const std::exception &e) {
        log_->error(e.what());
        return false;
      }
      return true;
    }

    bool PostgresWsvCommand::deleteAccountGrantablePermission(
        const std::string &permittee_account_id,
        const std::string &account_id,
        const std::string &permission_id) {
      try {
        transaction_.exec(
            "DELETE FROM public.account_has_grantable_permissions WHERE "
            "permittee_account_id="
            + try_quote(this, permittee_account_id)
            + " AND account_id=" + try_quote(this, account_id)
            + " AND permission_id=" + try_quote(this, permission_id) + " ;");
      } catch (const std::exception &e) {
        log_->error(e.what());
        return false;
      }
      return true;
    }

    bool PostgresWsvCommand::insertAccount(const model::Account &account) {
      try {
        transaction_.exec(
            "INSERT INTO account(account_id, domain_id, quorum, "
            "transaction_count, data) VALUES ("
            + try_quote(this, account.account_id) + ", "
            + try_quote(this, account.domain_id) + ", "
            + try_quote(this, account.quorum)
            + ", "
            // Transaction counter
            + try_quote(this, default_tx_counter) + ", "
            + try_quote(this, account.json_data) + ");");
      } catch (const std::exception &e) {
        log_->error(e.what());
        return false;
      }
      return true;
    }

    bool PostgresWsvCommand::insertAsset(const model::Asset &asset) {
      uint32_t precision = asset.precision;
      try {
        transaction_.exec(
            "INSERT INTO asset(asset_id, domain_id, \"precision\", data) "
            "VALUES ("
            + try_quote(this, asset.asset_id) + ", "
            + try_quote(this, asset.domain_id) + ", "
            + try_quote(this, precision) + ", " + /*asset.data*/ "NULL" + ");");
      } catch (const std::exception &e) {
        log_->error(e.what());
        return false;
      }
      return true;
    }

    bool PostgresWsvCommand::upsertAccountAsset(
        const model::AccountAsset &asset) {
      try {
        transaction_.exec(
            "INSERT INTO account_has_asset(account_id, asset_id, amount) "
            "VALUES ("
            + try_quote(this, asset.account_id) + ", "
            + try_quote(this, asset.asset_id) + ", "
            + try_quote(this, asset.balance.to_string())
            + ") ON CONFLICT (account_id, asset_id) DO UPDATE SET "
            "amount = EXCLUDED.amount;");
      } catch (const std::exception &e) {
        log_->error(e.what());
        return false;
      }
      return true;
    }

    bool PostgresWsvCommand::insertSignatory(const pubkey_t &signatory) {
      try {
        pqxx::binarystring public_key(signatory.data(), signatory.size());
        transaction_.exec("INSERT INTO signatory(public_key) VALUES ("
                          + try_quote(this, public_key)
                          + ") ON CONFLICT DO NOTHING;");
      } catch (const std::exception &e) {
        log_->error(e.what());
        return false;
      }
      return true;
    }

    bool PostgresWsvCommand::insertAccountSignatory(
        const std::string &account_id, const pubkey_t &signatory) {
      pqxx::binarystring public_key(signatory.data(), signatory.size());
      try {
        transaction_.exec(
            "INSERT INTO account_has_signatory(account_id, public_key) VALUES ("
            + try_quote(this, account_id) + ", " + try_quote(this, public_key)
            + ");");
      } catch (const std::exception &e) {
        log_->error(e.what());
        return false;
      }
      return true;
    }

    bool PostgresWsvCommand::deleteAccountSignatory(
        const std::string &account_id, const pubkey_t &signatory) {
      pqxx::binarystring public_key(signatory.data(), signatory.size());
      try {
        transaction_.exec(
            "DELETE FROM account_has_signatory WHERE account_id = "
            + try_quote(this, account_id)
            + " AND public_key = " + try_quote(this, public_key) + ";");
      } catch (const std::exception &e) {
        log_->error(e.what());
        return false;
      }
      return true;
    }

    bool PostgresWsvCommand::deleteSignatory(const pubkey_t &signatory) {
      pqxx::binarystring public_key(signatory.data(), signatory.size());
      try {
        transaction_.exec("DELETE FROM signatory WHERE public_key = "
            + try_quote(this, public_key)
            + " AND NOT EXISTS (SELECT 1 FROM account_has_signatory "
            "WHERE public_key = "
            + try_quote(this, public_key)
            + ") AND NOT EXISTS (SELECT 1 FROM peer WHERE public_key = "
            + try_quote(this, public_key) + ");");
      } catch (const std::exception &e) {
        log_->error(e.what());
        return false;
      }
      return true;
    }

    bool PostgresWsvCommand::insertPeer(const model::Peer &peer) {
      pqxx::binarystring public_key(peer.pubkey.data(), peer.pubkey.size());
      try {
        transaction_.exec("INSERT INTO peer(public_key, address) VALUES ("
                          + try_quote(this, public_key) + ", "
                          + try_quote(this, peer.address) + ");");
      } catch (const std::exception &e) {
        log_->error(e.what());
        return false;
      }
      return true;
    }

    bool PostgresWsvCommand::deletePeer(const model::Peer &peer) {
      pqxx::binarystring public_key(peer.pubkey.data(), peer.pubkey.size());
      try {
        transaction_.exec(
            "DELETE FROM peer WHERE public_key = " + try_quote(this, public_key)
            + " AND address = " + try_quote(this, peer.address) + ";");
      } catch (const std::exception &e) {
        log_->error(e.what());
        return false;
      }
      return true;
    }

    bool PostgresWsvCommand::insertDomain(const model::Domain &domain) {
      try {
        transaction_.exec("INSERT INTO domain(domain_id, default_role) VALUES ("
                          + try_quote(this, domain.domain_id) + ", "
                          + try_quote(this, domain.default_role) + ");");
      } catch (const std::exception &e) {
        log_->error(e.what());
        return false;
      }
      return true;
    }

    bool PostgresWsvCommand::updateAccount(const model::Account &account) {
      try {
        transaction_.exec(
            "UPDATE account\n"
            "   SET quorum=" +
            try_quote(this, account.quorum) +
            ", transaction_count=" +
            /*account.transaction_count*/ try_quote(this, default_tx_counter) +
            "\n"
            " WHERE account_id=" +
            try_quote(this, account.account_id) + ";");
      } catch (const std::exception &e) {
        log_->error(e.what());
        return false;
      }
      return true;
    }

    bool PostgresWsvCommand::setAccountKV(const std::string &account_id,
                                          const std::string &creator_account_id,
                                          const std::string &key,
                                          const std::string &val) {
      try {
        transaction_.exec(
            "UPDATE account SET data = jsonb_set(CASE WHEN data ?"
            + try_quote(this, creator_account_id)
            + " THEN data ELSE jsonb_set(data, "
            + try_quote(this, "{" + creator_account_id + "}") + ","
            + try_quote(this, "{}") + ") END,"
            + try_quote(this, "{" + creator_account_id + ", " + key + "}") + ","
            + try_quote(this, "\"" + val + "\"")
            + ") WHERE account_id=" + try_quote(this, account_id) + ";");
      } catch (const std::exception &e) {
        log_->error(e.what());
        return false;
      }
      return true;
    }

  }  // namespace ametsuchi
}  // namespace iroha
