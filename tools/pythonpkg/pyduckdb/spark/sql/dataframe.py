from pyduckdb.spark.exception import ContributionsAcceptedError

from typing import (
	TYPE_CHECKING,
	List
)

from pyduckdb.spark.sql.readwriter import DataFrameWriter
from pyduckdb.spark.sql.types import Row
import duckdb

if TYPE_CHECKING:
	from pyduckdb.spark.sql.session import SparkSession

class DataFrame:
	def __init__(self, relation: duckdb.DuckDBPyRelation, session: "SparkSession"):
		self.relation = relation
		self.session = session

	def show(self) -> None:
		self.relation.show()

	def createOrReplaceTempView(self, name: str) -> None:
		raise NotImplementedError

	def createGlobalTempView(self, name: str) -> None:
		raise NotImplementedError

	@property
	def write(self) -> DataFrameWriter:
		return DataFrameWriter(self)

	def printSchema(self):
		raise ContributionsAcceptedError

	def _cast_types(self, *types) -> "DataFrame":
		existing_columns = self.relation.columns
		types_count = len(types)
		assert types_count == len(existing_columns)
		cast_expressions = [f'"{existing}"::{target_type}' for existing, target_type in zip(existing_columns, types)]
		cast_expressions = ', '.join(cast_expressions)
		new_rel = self.relation.project(cast_expressions)
		return DataFrame(new_rel, self.session)

	def toDF(self, *cols) -> "DataFrame":
		existing_columns = self.relation.columns
		column_count = len(cols)
		assert column_count == len(existing_columns)
		projections = [f'"{existing}" as "{new}"' for existing, new in zip(existing_columns, cols)]
		projections = ', '.join(projections)
		new_rel = self.relation.project(projections)
		return DataFrame(new_rel, self.session)

	def collect(self) -> List[Row]:
		columns = self.relation.columns
		result = self.relation.fetchall()
		rows = [Row(**dict(zip(columns, x))) for x in result]
		return rows

__all__ = [
	"DataFrame"
]
