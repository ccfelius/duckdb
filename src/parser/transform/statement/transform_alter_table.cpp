#include "duckdb/parser/statement/alter_statement.hpp"
#include "duckdb/parser/transformer.hpp"
#include "duckdb/parser/expression/cast_expression.hpp"
#include "duckdb/parser/expression/columnref_expression.hpp"
#include "duckdb/parser/constraint.hpp"
#include "duckdb/parser/constraints/generated_constraint.hpp"

namespace duckdb {

unique_ptr<AlterStatement> Transformer::TransformAlter(duckdb_libpgquery::PGNode *node) {
	auto stmt = reinterpret_cast<duckdb_libpgquery::PGAlterTableStmt *>(node);
	D_ASSERT(stmt);
	D_ASSERT(stmt->relation);

	auto result = make_unique<AlterStatement>();

	auto qname = TransformQualifiedName(stmt->relation);

	// first we check the type of ALTER
	for (auto c = stmt->cmds->head; c != nullptr; c = c->next) {
		auto command = reinterpret_cast<duckdb_libpgquery::PGAlterTableCmd *>(lfirst(c));
		// TODO: Include more options for command->subtype
		switch (command->subtype) {
		case duckdb_libpgquery::PG_AT_AddColumn: {
			auto cdef = (duckdb_libpgquery::PGColumnDef *)command->def;
			auto centry = TransformColumnDefinition(cdef);

			bool default_constraint_set = false;
			unique_ptr<Constraint> generated_constraint = nullptr;
			if (cdef->constraints) {
				for (auto constr = cdef->constraints->head; constr != nullptr; constr = constr->next) {
					auto constraint = TransformConstraint(constr, centry, 0);
					default_constraint_set =
					    default_constraint_set || ConstraintIsOfType(constr, duckdb_libpgquery::PG_CONSTR_DEFAULT);
					if (!constraint) {
						continue;
					}
					if (constraint->type == ConstraintType::GENERATED && !generated_constraint) {
						generated_constraint = move(constraint);
					} else {
						throw ParserException("Adding columns with constraints not yet supported");
					}
				}
			}
			if (generated_constraint) {
				D_ASSERT(generated_constraint->type == ConstraintType::GENERATED);
				if (default_constraint_set) {
					throw BinderException("DEFAULT constraint on GENERATED column \"%s\" is not allowed", centry.name);
				}
				auto gen_constraint = (GeneratedConstraint *)generated_constraint.get();
				auto generated_column =
				    GeneratedColumnDefinition(centry.name, move(centry.type), move(gen_constraint->expression));
				result->info = make_unique<AddGeneratedColumnInfo>(qname.schema, qname.name, move(generated_column));
			} else {
				result->info = make_unique<AddColumnInfo>(qname.schema, qname.name, move(centry));
			}
			break;
		}
		case duckdb_libpgquery::PG_AT_DropColumn: {
			bool cascade = command->behavior == duckdb_libpgquery::PG_DROP_CASCADE;
			result->info =
			    make_unique<RemoveColumnInfo>(qname.schema, qname.name, command->name, command->missing_ok, cascade);
			break;
		}
		case duckdb_libpgquery::PG_AT_ColumnDefault: {
			auto expr = TransformExpression(command->def);
			result->info = make_unique<SetDefaultInfo>(qname.schema, qname.name, command->name, move(expr));
			break;
		}
		case duckdb_libpgquery::PG_AT_AlterColumnType: {
			bool cascade = command->behavior == duckdb_libpgquery::PG_DROP_CASCADE;
			auto cdef = (duckdb_libpgquery::PGColumnDef *)command->def;
			auto column_definition = TransformColumnDefinition(cdef);

			unique_ptr<ParsedExpression> expr;
			if (cdef->raw_default) {
				expr = TransformExpression(cdef->raw_default);
			} else {
				auto colref = make_unique<ColumnRefExpression>(command->name);
				expr = make_unique<CastExpression>(column_definition.type, move(colref));
			}
			result->info = make_unique<ChangeColumnTypeInfo>(qname.schema, qname.name, command->name,
			                                                 column_definition.type, move(expr), cascade);
			break;
		}
		case duckdb_libpgquery::PG_AT_DropConstraint:
		case duckdb_libpgquery::PG_AT_DropNotNull:
		default:
			throw NotImplementedException("ALTER TABLE option not supported yet!");
		}
	}

	return result;
}

} // namespace duckdb
